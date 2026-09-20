// 权限工具：基于角色与文档可见性
import { isShareActive, canShareEdit } from './share'
import { isDocInReview } from './review'
import { isGrantActive, ACCESS_PERM } from './access'

export const ROLE = { ADMIN: 'admin', EDITOR: 'editor', VIEWER: 'viewer' }
export const GUEST_ID = 'u-guest'

// 是否为已登录成员（访客 id 缺省或为 u-guest 一律按访客处理）
export function isLoginUser(userId) {
  return !!userId && userId !== GUEST_ID
}

// 可新增/编辑/删除的（内容治理）
export function canEditContent(role) {
  return role === ROLE.ADMIN || role === ROLE.EDITOR
}

// 文档协作资格（与评审锁定无关的文档级写入身份）：
// 管理员 / 拥有者 / 固定协作成员 / 持有效限时协作（collab）授权。
// 仅 editor 角色但不是该文档协作者的人不据此放行；「公开可编辑」概念本系统不提供，
// 公开/团队仅决定可见性，编辑一律走文档级身份，普通编辑与共享编辑共用同一道校验。
export function hasDocWriteIdentity(role, doc, userId, grant) {
  if (!doc || !isLoginUser(userId)) return false
  if (role === ROLE.ADMIN) return true
  if (doc.ownerId === userId) return true
  if (doc.editors && doc.editors.includes(userId)) return true
  // 限时协作授权：授权期内放开编辑（只读角色也能协作）；read 授权或已撤销/到期不放开
  if (isGrantActive(grant) && grant.grant?.permission === ACCESS_PERM.COLLAB) return true
  return false
}

// 文档编辑者：拥有者 / 固定协作成员 / 持限时协作授权（collab）/ 管理员 / 凭有效可编辑共享链接。
// pendingReview 非空表示该文档有流转中的评审单：评审中锁定编辑，仅管理员可继续直接改动。
// 限时协作授权与共享编辑是成员/链接级例外：只读角色、访客在授权（链接）有效期内也可编辑该文档，
// 但同样受评审锁定约束。share 仅在共享链接编辑场景传入（须 active + permission=edit）。
export function canEditDoc(role, doc, userId, pendingReview, grant, share) {
  if (!doc) return false
  // 管理员不受评审锁定；其余人在评审中一律不能直接改（授权成员、可编辑共享链接也不例外，审批通过后恢复）
  if (isDocInReview(doc, pendingReview) && role !== ROLE.ADMIN) return false
  if (hasDocWriteIdentity(role, doc, userId, grant)) return true
  // 凭有效「可编辑」共享链接：访客/非协作者可编辑，但链接撤销/过期或评审锁定后立即收回
  if (canShareEdit(share)) return true
  return false
}

// 能否发起文档送审（普通评审 / 版本恢复评审 / 工单关联送审共用同一道校验）：
// 已登录的内容角色（editor/admin）、对该文档有协作身份（拥有者/固定协作者/有效 collab 授权），
// 且当前没有流转中的评审单。共享链接编辑是「直接发布」通道，不提供送审入口；
// 仅持 read 授权、授权已撤销/到期、非协作者一律不能送审（避免未授权内容经审批发布）。
export function canSubmitDocReview(role, doc, userId, pendingReview, grant) {
  if (!doc || !isLoginUser(userId) || !canEditContent(role)) return false
  if (isDocInReview(doc, pendingReview)) return false
  return hasDocWriteIdentity(role, doc, userId, grant)
}

// 是否可查看某文档（可见性 + 拥有者 + 协作成员 + 有效限时授权 + 有效共享链接）
// grant：该用户在该文档上的访问申请记录（approved 且未撤销/未到期才授权）
export function canViewDoc(doc, userId, share, grant, now) {
  if (!doc) return false
  if (doc.visibility === 'public') return true
  if (doc.visibility === 'team') {
    // team 指全员可见（演示简化：所有登录成员可见）
    return true
  }
  // private：拥有者、固定协作成员、限时授权成员可见（或持有效共享链接——已撤销/已过期不授权）
  if (doc.ownerId === userId) return true
  if (doc.editors && doc.editors.includes(userId)) return true
  if (isGrantActive(grant, now)) return true
  if (isShareActive(share)) return true
  return false
}

export function canDeleteDoc(role, doc, userId) {
  return canEditDoc(role, doc, userId)
}

export function roleLabel(role) {
  return { admin: '管理员', editor: '编辑者', viewer: '只读' }[role] || role
}
