// 文档编辑与评审越权边界：端到端安全测试（fake-indexeddb + 真实 store）
// 覆盖：访客直改/共享链接、评审锁定、限时授权撤销/到期/read 授权、
//       普通编辑越权他人文档、送审身份、越权审批与联动工单结案
// 运行：npm run test:security（esbuild 打包后在 node 中执行）
import 'fake-indexeddb/auto'
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { db } from '@/db'
import { useGapStore } from '@/stores/gap'
import { useReviewStore } from '@/stores/review'
import { useKbStore } from '@/stores/kb'
import { useAccessStore } from '@/stores/access'
import { PUBLISH } from '@/utils/review'
import { ACCESS, ACCESS_PERM } from '@/utils/access'
import {
  canEditDoc, canViewDoc, canSubmitDocReview, hasDocWriteIdentity, isLoginUser
} from '@/utils/permission'

const pinia = createPinia()
createApp({ render: () => null }).use(pinia)
const gap = useGapStore(pinia)
const review = useReviewStore(pinia)
const kb = useKbStore(pinia)
const access = useAccessStore(pinia)

const admin = { id: 'u-admin', role: 'admin', name: '管理员' }
const editor = { id: 'u-chen', role: 'editor', name: '编辑甲' }
const editor2 = { id: 'u-ziwei', role: 'editor', name: '编辑乙' }
const viewer = { id: 'u-mochen', role: 'viewer', name: '只读成员' }
const guest = { id: 'u-guest', role: 'viewer', name: '访客' }
const noUser = null

let passed = 0
let failed = 0
function assert(cond, msg) {
  if (cond) { passed++; console.log('  ✅', msg) }
  else { failed++; console.error('  ❌', msg) }
}

function iso(offsetMs) { return new Date(Date.now() + offsetMs).toISOString() }

// 造一篇私有文档：拥有者 editor，固定协作者仅 editor
async function mkPrivateDoc(id, extra = {}) {
  const doc = {
    id, title: '私有文档 ' + id, body: '<p>原始正文</p>', categoryId: 'c-dev', tagIds: [],
    visibility: 'private', ownerId: editor.id, editors: [editor.id],
    publishState: PUBLISH.PUBLISHED, activeReviewId: null,
    createdAt: iso(-86400000), updatedAt: iso(-3600000),
    versions: [{ version: 1, savedAt: iso(-3600000), savedBy: editor.id, note: '初始', snapshot: { title: '私有文档 ' + id, body: '<p>原始正文</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' } }],
    ...extra
  }
  await db.docs.add(doc)
  await kb.reloadDocs()
  return doc
}

async function mkShare(docId, permission, extra = {}) {
  const s = { id: 'sh-' + Math.random().toString(36).slice(2), docId, token: 'tok-' + Math.random().toString(36).slice(2), permission, createdBy: editor.id, createdAt: iso(-3600000), expiresAt: null, revokedAt: null, ...extra }
  await db.shares.add(s)
  return s
}

const patchBody = (b) => ({ body: b })

// ---------- 1. 访客边界 ----------
console.log('\n[1] 访客：不得直改正文、新建、送审、评论、审批')
const d1 = await mkPrivateDoc('doc-sec-1')
let r = await kb.updateDoc(d1.id, patchBody('<p>访客改的</p>'), noUser, '访客直改')
assert(r.status === 'access-denied', '未登录（null）直改被拒')
assert((await db.docs.get(d1.id)).body === '<p>原始正文</p>', '未登录直改未写入')

r = await kb.updateDoc(d1.id, patchBody('<p>访客改的</p>'), guest, '访客直改')
assert(r.status === 'access-denied', 'u-guest 直改被拒（不再因 guest 而跳过校验）')

const cd = await kb.createDoc({ title: 'x', body: 'y' }, guest)
assert(cd.status === 'access-denied', '访客新建文档被拒')

r = await review.submitReview(d1.id, { title: d1.title, body: '<p>访客送审</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '', guest)
assert(r.status === 'guest', '访客发起评审被拒')

r = await review.decideReview('nonexistent', 'approve', '', guest)
assert(['missing', 'denied'].includes(r.status) && r.status !== 'ok', '访客审批不产生发布')

// 先由合法编辑者建一条评审，再验证访客不能评论/审批
r = await review.submitReview(d1.id, { title: d1.title, body: '<p>编辑送审内容</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '请审批', editor)
assert(r.status === 'ok', '合法编辑者发起评审成功')
const rev1 = r.review
const cm = await review.addReviewComment(rev1.id, '访客意见', [], guest)
assert(cm === null, '访客发表评审意见被拒')
r = await review.decideReview(rev1.id, 'approve', '', guest)
assert(r.status === 'denied' && (await db.docs.get(d1.id)).body === '<p>原始正文</p>', '访客审批被拒，内容未发布')
// 驳回掉该评审，便于后续用例
await review.decideReview(rev1.id, 'reject', '', admin)

// ---------- 2. 普通编辑越权他人私有文档 ----------
console.log('\n[2] 普通编辑：非协作者不得改/送审他人私有文档')
const d2 = await mkPrivateDoc('doc-sec-2')
assert(hasDocWriteIdentity(editor2.role, d2, editor2.id, null) === false, '编辑乙对甲的私有文档无协作身份')
r = await kb.updateDoc(d2.id, patchBody('<p>乙偷改</p>'), editor2, '越权直改')
assert(r.status === 'access-denied', '非协作者 editor 角色直改被拒（不再仅因角色放行）')
assert((await db.docs.get(d2.id)).body === '<p>原始正文</p>', '越权直改未写入')
r = await review.submitReview(d2.id, { title: d2.title, body: '<p>乙越权送审</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '', editor2)
assert(r.status === 'denied', '非协作者 editor 送审被拒')
// 只读角色同样
r = await kb.updateDoc(d2.id, patchBody('<p>只读改</p>'), viewer, '只读直改')
assert(r.status === 'access-denied', '只读角色无授权直改被拒')

// ---------- 3. 评审锁定边界 ----------
console.log('\n[3] 评审锁定：拥有者/协作者/授权/共享链接均被锁，仅管理员可直改')
const d3 = await mkPrivateDoc('doc-sec-3')
const sub = await review.submitReview(d3.id, { title: d3.title, body: '<p>待审</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '', editor)
assert(sub.status === 'ok', 'd3 进入评审中')
assert(canEditDoc(editor.role, d3, editor.id, { id: 'x' }) === false, '拥有者在评审中被锁（纯函数）')

r = await kb.updateDoc(d3.id, patchBody('<p>拥有者强改</p>'), editor, '锁定期改')
assert(r.status === 'review-locked', '拥有者在评审中直改被拒')
assert((await db.docs.get(d3.id)).body === '<p>原始正文</p>', '锁定期拥有者修改未写入')

// 可编辑共享链接也必须被评审锁挡住
const editShare = await mkShare(d3.id, 'edit')
r = await kb.updateDoc(d3.id, patchBody('<p>访客借链接改</p>'), guest, '共享链接编辑', { share: editShare })
assert(r.status === 'review-locked', '评审中可编辑共享链接同样被锁')

// 管理员可在评审中直改
r = await kb.updateDoc(d3.id, patchBody('<p>管理员直改</p>'), admin, '管理员直改')
assert(r.status === 'saved', '管理员评审中可直改')
assert((await db.docs.get(d3.id)).body === '<p>管理员直改</p>', '管理员直改写入成功')

// ---------- 4. 共享编辑链接：有效可编辑、只读链接/撤销/过期不可 ----------
console.log('\n[4] 共享链接：edit 生效；view/撤销/过期不授权写入')
const d4 = await mkPrivateDoc('doc-sec-4')
const shareEdit = await mkShare(d4.id, 'edit')
r = await kb.updateDoc(d4.id, patchBody('<p>链接编辑</p>'), guest, '共享链接编辑', { share: shareEdit })
assert(r.status === 'saved' && (await db.docs.get(d4.id)).body === '<p>链接编辑</p>', '有效 edit 链接可写入（访客身份）')

const shareView = await mkShare(d4.id, 'view')
r = await kb.updateDoc(d4.id, patchBody('<p>view 链接改</p>'), guest, '只读链接编辑', { share: shareView })
assert(r.status === 'access-denied', 'view 链接不可写入')

const shareRevoked = await mkShare(d4.id, 'edit', { revokedAt: iso(-1000) })
r = await kb.updateDoc(d4.id, patchBody('<p>撤销链接改</p>'), guest, '撤销链接编辑', { share: shareRevoked })
assert(r.status === 'access-denied', '已撤销链接不可写入')

const shareExpired = await mkShare(d4.id, 'edit', { expiresAt: iso(-1000) })
r = await kb.updateDoc(d4.id, patchBody('<p>过期链接改</p>'), guest, '过期链接编辑', { share: shareExpired })
assert(r.status === 'access-denied', '已过期链接不可写入')

// 不传凭证：访客无法借「曾经有过链接」写入
r = await kb.updateDoc(d4.id, patchBody('<p>无凭证改</p>'), guest, '无凭证')
assert(r.status === 'access-denied', '无 share 凭证访客不可写入')

// 链接在编辑期间被撤销：保存瞬间被拒
const shareEdit2 = await mkShare(d4.id, 'edit')
await db.shares.update(shareEdit2.id, { revokedAt: iso(-500) })
r = await kb.updateDoc(d4.id, patchBody('<p>中途撤销</p>'), guest, '中途撤销', { share: shareEdit2 })
assert(r.status === 'access-denied', '链接在保存前被撤销，事务内复核拒绝')

// ---------- 5. 限时协作授权：生效可改，撤销/到期/read 不可 ----------
console.log('\n[5] 限时授权：collab 生效可编辑；撤销/到期/read 授权立即收回')
const d5 = await mkPrivateDoc('doc-sec-5')
await access.loadAll()
// viewer 申请 collab，拥有者 admin 审批通过
let ar = await access.createRequest(d5.id, ACCESS_PERM.COLLAB, '协作', viewer)
assert(ar.status === 'ok', '只读成员提交协作申请')
ar = await access.decideRequest(ar.request.id, 'approve', '', 1, admin)
assert(ar.status === 'ok', '协作授权审批通过（1 天）')
const grantId = ar.request.id
const grantActive = await db.accessRequests.get(grantId)
assert(canEditDoc(viewer.role, d5, viewer.id, null, grantActive) === true, '纯函数：collab 授权内可编辑')
r = await kb.updateDoc(d5.id, patchBody('<p>授权协作改</p>'), viewer, '协作编辑')
assert(r.status === 'saved', 'collab 授权期内只读成员可直改')
assert((await db.docs.get(d5.id)).body === '<p>授权协作改</p>', '协作编辑写入成功')

// 撤销后立即收回
await access.revokeGrant(grantId, '提前收回', admin)
r = await kb.updateDoc(d5.id, patchBody('<p>撤销后改</p>'), viewer, '撤销后')
assert(r.status === 'access-denied', '授权撤销后保存被拒')
assert((await db.docs.get(d5.id)).body === '<p>授权协作改</p>', '撤销后修改未写入')
assert(canViewDoc(d5, viewer.id, null, await db.accessRequests.get(grantId)) === false, '撤销后私有文档不可见')

// 到期授权（惰性）：记录仍 approved 但判定失效
const d5b = await mkPrivateDoc('doc-sec-5b')
const expiredReq = {
  id: 'acc-exp', docId: d5b.id, applicantId: viewer.id, status: ACCESS.APPROVED,
  requestedPermission: ACCESS_PERM.COLLAB, reason: '', createdAt: iso(-86400000 * 2),
  decidedBy: admin.id, decidedAt: iso(-86400000 * 2 - 3600000), decisionNote: '',
  expiresAt: iso(-3600000), revokedAt: null,
  grant: { permission: ACCESS_PERM.COLLAB, grantedAt: iso(-86400000 * 2), expiresAt: iso(-3600000), revokedAt: null },
  timeline: []
}
await db.accessRequests.add(expiredReq)
r = await kb.updateDoc(d5b.id, patchBody('<p>到期改</p>'), viewer, '到期后')
assert(r.status === 'access-denied', '授权到期后保存被拒（惰性失效）')
assert((await db.docs.get(d5b.id)).body === '<p>原始正文</p>', '到期后修改未写入')
assert(canViewDoc(d5b, viewer.id, null, expiredReq) === false, '到期后私有文档不可见')

// read 授权不能编辑
const d5c = await mkPrivateDoc('doc-sec-5c')
const readReq = await access.createRequest(d5c.id, ACCESS_PERM.READ, '只读', viewer)
await access.decideRequest(readReq.request.id, 'approve', '', 1, admin)
const readGrant = await db.accessRequests.get(readReq.request.id)
assert(canEditDoc(viewer.role, d5c, viewer.id, null, readGrant) === false, 'read 授权不可编辑')
assert(canViewDoc(d5c, viewer.id, null, readGrant) === true, 'read 授权可查看')
r = await kb.updateDoc(d5c.id, patchBody('<p>read 想改</p>'), viewer, 'read 改')
assert(r.status === 'access-denied', '仅 read 授权直改被拒')
// read 授权不能送审
assert(canSubmitDocReview(viewer.role, d5c, viewer.id, null, readGrant) === false, 'viewer 持 read 授权不能送审')

// collab 授权的只读成员：可直改，但不能发起评审（UI 强制 save 模式，store 也拒）
assert(canSubmitDocReview(viewer.role, d5, viewer.id, null, null) === false, '只读角色即便有协作身份也不走送审通道（角色门）')

// ---------- 6. 越权审批与联动工单结案 ----------
console.log('\n[6] 越权审批：非管理员不能通过评审，缺口工单不得被联动结案')
await gap.loadAll()
const tk = await gap.createTicket({ question: '越权审批专用问题 ' + Math.random(), detail: '' }, viewer)
await gap.claimTicket(tk.ticket.id, editor)
const d6 = await mkPrivateDoc('doc-sec-6')
const gs = await review.submitGapReview(tk.ticket.id, d6.id, { title: d6.title, body: '<p>工单送审内容</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '送审', editor)
assert(gs.status === 'ok', '工单关联送审成功')
const gRev = gs.review

// editor2（非管理员、非拥有者）尝试审批通过
r = await review.decideReview(gRev.id, 'approve', '越权通过', editor2)
assert(r.status === 'denied', '非管理员审批被拒')
const tkAfter = await db.gapTickets.get(tk.ticket.id)
assert(tkAfter.status === 'in_review', '越权审批未把工单联动结案')
assert((await db.docs.get(d6.id)).body === '<p>原始正文</p>', '越权审批未发布内容')

// viewer / guest 审批同样被拒
r = await review.decideReview(gRev.id, 'approve', '', viewer)
assert(r.status === 'denied', '只读角色审批被拒')

// 只读/访客认领工单被拒（不能进入送审链路）
const tk2 = await gap.createTicket({ question: '认领越权问题 ' + Math.random(), detail: '' }, viewer)
r = await gap.claimTicket(tk2.ticket.id, viewer)
assert(r.status === 'denied', '只读角色认领工单被拒')
r = await gap.claimTicket(tk2.ticket.id, guest)
assert(r.status === 'denied', '访客认领工单被拒')

// 非协作者把他人私有文档拿去送审被拒，且不锁文档、不建工单关联
await gap.claimTicket(tk2.ticket.id, editor2)
const d7 = await mkPrivateDoc('doc-sec-7', { ownerId: editor.id, editors: [editor.id] })
r = await review.submitGapReview(tk2.ticket.id, d7.id, { title: d7.title, body: '<p>乙拿甲文档送审</p>', categoryId: 'c-dev', tagIds: [], visibility: 'private' }, '', editor2)
assert(r.status === 'denied', '非协作者不能把他人私有文档关联送审')
const d7fresh = await db.docs.get(d7.id)
assert(d7fresh.activeReviewId == null && d7fresh.publishState === PUBLISH.PUBLISHED, '被拒送审未锁定文档')
const tk2fresh = await db.gapTickets.get(tk2.ticket.id)
assert(tk2fresh.status === 'claimed' && !tk2fresh.reviewId, '被拒送审未在工单上残留评审关联')

// 正路：管理员审批通过，工单才结案并回填
r = await review.decideReview(gRev.id, 'approve', '通过', admin)
assert(r.status === 'ok', '管理员审批通过')
const tkResolved = await db.gapTickets.get(tk.ticket.id)
assert(tkResolved.status === 'resolved' && tkResolved.docId === d6.id && !!tkResolved.resolvedAt, '管理员通过后工单才结案回填')
assert((await db.docs.get(d6.id)).body === '<p>工单送审内容</p>', '审批通过内容发布')

// ---------- 7. 纯函数：isLoginUser 与管理员身份 ----------
console.log('\n[7] 基础判定：访客识别与管理员协作身份')
assert(isLoginUser(null) === false && isLoginUser('u-guest') === false && isLoginUser('u-chen') === true, 'isLoginUser 正确识别访客')
const d8 = await mkPrivateDoc('doc-sec-8')
assert(hasDocWriteIdentity(admin.role, d8, admin.id, null) === true, '管理员对任意文档有协作身份')
assert(hasDocWriteIdentity(editor.role, d8, editor.id, null) === true, '拥有者有协作身份')
assert(canSubmitDocReview(admin.role, d8, admin.id, null, null) === true, '管理员可送审')
assert(canSubmitDocReview(viewer.role, d8, viewer.id, null, null) === false, '只读角色不可送审')
assert(canSubmitDocReview(null, d8, null, null, null) === false, '访客不可送审')

console.log(`\n结果：${passed} 通过，${failed} 失败`)
process.exit(failed ? 1 : 0)
