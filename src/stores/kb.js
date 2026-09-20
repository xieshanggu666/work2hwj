import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { db } from '@/db'
import { uid } from '@/utils/format'
import { ensureVersions, mergeDocFields, docSnapshot } from '@/utils/version'
import { buildTimelineEntry } from '@/utils/review'
import { GAP } from '@/utils/gap'
import { isGrantActive, ACCESS_PERM } from '@/utils/access'
import { canShareEdit } from '@/utils/share'
import { ROLE, GUEST_ID, isLoginUser } from '@/utils/permission'
import { useAuthStore } from './auth'
import { useGapStore } from './gap'

// 库内写入鉴权（权威防线，UI 判定可被多窗口/直接调用绕过，所有写库前必须在此复核）。
// 在写事务内、对「最新读到的文档」判定，保证撤销/到期/锁定等并发变化即时生效：
// - 访客（无 id 或 u-guest）一律拒绝写文档（唯一例外是持有效可编辑共享链接的直改）
// - 评审锁定（activeReviewId 存在）：仅管理员可直改；共享链接编辑同样被锁
// - 文档协作身份：管理员 / 拥有者 / 固定协作成员 / 有效 collab 授权
// - 共享编辑：提供了 active + permission=edit 的 share 记录（直改正文，不走送审）。
//   事务内按 token 重读最新链接，编辑期间被撤销/过期也能即时收回（不信任传入的内存快照）。
// 返回 null 表示放行，否则为拒绝原因（access-denied / review-locked）
async function checkDocWriteAuth(existing, currentUser, share) {
  const userId = currentUser?.id
  const role = currentUser?.role

  // 共享编辑通道：按 token 事务内重读最新链接状态
  let freshShare = null
  if (share?.token) {
    freshShare = await db.shares.where('token').equals(share.token).first()
    // 链接必须仍归属该文档，防止拿 A 文档的有效链接去写 B 文档
    if (!freshShare || freshShare.docId !== existing.id) freshShare = null
  }

  if (!isLoginUser(userId) && !canShareEdit(freshShare)) return 'access-denied'

  // 评审锁定优先：评审中仅管理员可直改（管理员写入通道为审批，这里兜底防御多窗口/共享链接绕过）
  if (existing.activeReviewId && role !== ROLE.ADMIN) return 'review-locked'

  if (role === ROLE.ADMIN) return null
  if (existing.ownerId === userId) return null
  if ((existing.editors || []).includes(userId)) return null

  // 限时协作授权：事务内查最新授权记录，撤销/到期/read 授权均不放行
  const reqs = await db.accessRequests
    .where('docId').equals(existing.id)
    .filter((r) => r.applicantId === userId).toArray()
  const collab = reqs.find((r) => isGrantActive(r) && r.grant?.permission === ACCESS_PERM.COLLAB)
  if (collab) return null

  // 有效可编辑共享链接（访客/非协作者可直接改正文，链接撤销/过期即收回）
  if (canShareEdit(freshShare)) return null

  return 'access-denied'
}

export const useKbStore = defineStore('kb', () => {
  const docs = ref([])
  const categories = ref([])
  const tags = ref([])
  const comments = ref([])
  const loaded = ref(false)

  const catMap = computed(() => Object.fromEntries(categories.value.map((c) => [c.id, c])))
  const tagMap = computed(() => Object.fromEntries(tags.value.map((t) => [t.id, t])))

  async function loadAll() {
    if (loaded.value) return
    docs.value = await db.docs.toArray()
    categories.value = await db.categories.toArray()
    tags.value = await db.tags.toArray()
    comments.value = await db.comments.toArray()
    loaded.value = true
  }

  async function reloadDocs() {
    docs.value = await db.docs.toArray()
  }

  async function getDoc(id) {
    await loadAll()
    return docs.value.find((d) => d.id === id) || null
  }

  // 直接读库取最新文档，绕过内存缓存——编辑器打开文档、保存前校验时必须用最新数据，
  // 否则多窗口场景会基于过期快照判断，造成覆盖与版本记录丢失
  async function getDocFresh(id) {
    await loadAll()
    const fresh = await db.docs.get(id)
    return fresh || null
  }

  async function createDoc(payload, currentUser) {
    await loadAll()
    const now = new Date().toISOString()
    const userId = currentUser?.id
    // 访客与只读角色不得新建文档（路由 meta 是第一道，此处为写库前的权威校验）
    if (!isLoginUser(userId) || !(currentUser?.role === ROLE.ADMIN || currentUser?.role === ROLE.EDITOR)) {
      return { status: 'access-denied' }
    }
    const doc = {
      id: uid('doc'),
      title: payload.title || '无标题文档',
      categoryId: payload.categoryId || categories.value[0]?.id || null,
      tagIds: payload.tagIds || [],
      body: payload.body || '',
      visibility: payload.visibility || 'public',
      publishState: 'published',
      activeReviewId: null,
      ownerId: userId,
      editors: [userId],
      createdAt: now,
      updatedAt: now,
      versions: [{ version: 1, savedAt: now, savedBy: userId, note: '创建文档', snapshot: docSnapshot(payload) }]
    }
    await db.docs.add(doc)
    await reloadDocs()
    return doc
  }

  // 保存文档（乐观锁 + 三方合并）。
  // opts.baseVersion：编辑器打开文档时的版本号；保存时若库中版本更高，说明其他窗口已保存过
  // opts.base：编辑器打开时的字段快照，用于三方合并（只自动合并未被对方改动的字段）
  // opts.force：用户确认「以我的内容为准」时强制保存，冲突字段取本次提交值
  // opts.share：共享链接编辑凭证（share 记录）；仅 active + permission=edit 才授权直改
  // 返回 { status: 'saved', doc, autoMerged } | { status: 'conflict', conflictFields, autoMerged, latest }
  //      | { status: 'missing' } | { status: 'access-denied', latest } | { status: 'review-locked', latest }
  async function updateDoc(id, patch, currentUser, note, opts = {}) {
    await loadAll()
    const now = new Date().toISOString()
    const savedBy = currentUser?.id || GUEST_ID
    let result = null
    // 读 + 写放在同一事务中，保证「鉴权 → 检测版本 → 合并 → 追加版本记录」不被其他窗口的写入打断
    await db.transaction('rw', db.docs, db.accessRequests, db.shares, async () => {
      const existing = await db.docs.get(id)
      if (!existing) { result = { status: 'missing' }; return }
      // 统一写入鉴权：访客/非协作者/授权失效拒绝；评审锁定仅管理员可直改；共享链接撤销过期即收回。
      // 在事务内对最新文档复核，防止前端入口放开后被多窗口/直接调用绕过
      const denied = await checkDocWriteAuth(existing, currentUser, opts.share)
      if (denied) { result = { status: denied, latest: existing }; return }
      // 兼容已有文档：缺失的版本记录先补全，再在其后追加，历史版本永不丢弃
      const versions = ensureVersions(existing, now)
      const currentVersion = versions.length
      const hasConflict = opts.baseVersion != null && currentVersion > opts.baseVersion

      let fields = patch
      let autoMerged = []
      if (hasConflict) {
        if (!opts.base) {
          // 没有基线快照无法安全合并，除非强制保存，否则返回冲突由调用方决定
          if (!opts.force) {
            result = { status: 'conflict', conflictFields: Object.keys(patch), autoMerged, latest: existing }
            return
          }
        } else {
          const merge = mergeDocFields(existing, opts.base, patch)
          autoMerged = merge.autoMerged
          if (merge.conflicts.length && !opts.force) {
            result = { status: 'conflict', conflictFields: merge.conflicts, autoMerged, latest: existing }
            return
          }
          fields = merge.fields
          // 用户选择以本次提交为准：冲突字段强制采用我方值，其余字段仍是合并结果
          if (opts.force) for (const k of merge.conflicts) fields[k] = patch[k]
        }
      }

      const versionNote = autoMerged.length
        ? (note || '编辑文档') + '（自动合并：' + autoMerged.join('、') + '）'
        : (note || '编辑文档')
      const updated = {
        ...existing,
        ...fields,
        updatedAt: now,
        // 版本记录升级为内容快照：保存后的完整字段随版本留档，供历史对比与恢复评审使用
        versions: [...versions, { version: currentVersion + 1, savedAt: now, savedBy, note: versionNote, snapshot: docSnapshot({ ...existing, ...fields }) }]
      }
      await db.docs.put(updated)
      result = { status: 'saved', doc: updated, autoMerged }
    })
    await reloadDocs()
    return result
  }

  async function deleteDoc(id) {
    await db.docs.delete(id)
    await db.comments.where('docId').equals(id).delete()
    await db.shares.where('docId').equals(id).delete()
    // 评审单随文档一并清理（直接按索引删除，避免与 review store 循环依赖）
    await db.reviews.where('docId').equals(id).delete()
    // 访问申请/授权随文档一并清理（授权失去依附对象，详情、搜索、问答、编辑入口同步消失）
    await db.accessRequests.where('docId').equals(id).delete()
    // 关联该文档的缺口工单退回处理中：答案来源/送审关联随文档删除失效，需重新关联
    const now = new Date().toISOString()
    const linkedTickets = await db.gapTickets.where('docId').equals(id).toArray()
    for (const t of linkedTickets) {
      await db.gapTickets.update(t.id, {
        status: GAP.CLAIMED,
        docId: null,
        reviewId: null,
        resolvedAt: null,
        timeline: [...(t.timeline || []), buildTimelineEntry('reset', 'system', '关联文档已删除，工单退回处理', now)]
      })
    }
    comments.value = comments.value.filter((c) => c.docId !== id)
    const gap = useGapStore()
    await Promise.all([reloadDocs(), gap.reload()])
  }

  async function addCategory(name, icon) {
    const cat = { id: uid('c'), name, icon: icon || 'doc' }
    await db.categories.add(cat)
    categories.value.push(cat)
    return cat
  }

  async function addTag(name, color) {
    const tag = { id: uid('t'), name, color: color || '#4f6ef7' }
    await db.tags.add(tag)
    tags.value.push(tag)
    return tag
  }

  // ---- 评论 ----
  async function addComment(docId, content, mentionIds, authorId) {
    const cmt = { id: uid('cmt'), docId, authorId, content, mentionIds: mentionIds || [], createdAt: new Date().toISOString() }
    await db.comments.add(cmt)
    comments.value.push(cmt)
    return cmt
  }

  function commentsOf(docId) {
    return comments.value
      .filter((c) => c.docId === docId)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
  }

  return {
    docs, categories, tags, comments, loaded,
    catMap, tagMap, loadAll, reloadDocs, getDoc, getDocFresh, createDoc, updateDoc, deleteDoc,
    addCategory, addTag, addComment, commentsOf
  }
})