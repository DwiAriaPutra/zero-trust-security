export type PolicyDecision = "ALLOW" | "DENY";
export type PolicyRole = "ADMIN" | "DOSEN" | "MAHASISWA";

export interface PolicySubject {
  id: string;
  role: PolicyRole;
  accountActive: boolean;
}

export interface PolicyDevice {
  id: string;
  userId: string;
  active: boolean;
}

export interface PolicyResource {
  type: string;
  id: string;
  ownerId?: string;
  classId?: string;
  teacherId?: string;
  enrolled?: boolean;
  classFinalized?: boolean;
  finalizationPending?: boolean;
  finalizationComplete?: boolean;
}

export interface AccessWindow {
  startTime: string;
  endTime: string;
  timezone: string;
}

export interface PolicyContext {
  currentTime?: Date;
  accessWindow?: AccessWindow;
}

export interface PolicyRequest {
  subject: PolicySubject;
  device: PolicyDevice;
  action: string;
  resource: PolicyResource;
  context?: PolicyContext;
}

export interface PolicyResult {
  decision: PolicyDecision;
  reasonCode: string;
}

export const DEFAULT_ACCESS_WINDOW: AccessWindow = {
  startTime: "07:00",
  endTime: "21:00",
  timezone: "Asia/Jakarta"
};

type RuleCondition = "OWNER" | "CLASS_TEACHER" | "CLASS_TEACHER_MUTABLE" | "CLASS_TEACHER_FINALIZE" | "ADMIN";

interface PolicyRule {
  role: PolicyRole;
  action: string;
  resourceType: string;
  condition: RuleCondition;
}

const RULES: readonly PolicyRule[] = [
  { role: "MAHASISWA", action: "grade:read", resourceType: "grade", condition: "OWNER" },
  { role: "MAHASISWA", action: "grade:list", resourceType: "grade-list", condition: "OWNER" },
  { role: "MAHASISWA", action: "transcript:read", resourceType: "transcript", condition: "OWNER" },
  { role: "DOSEN", action: "grade:read", resourceType: "grade", condition: "CLASS_TEACHER" },
  { role: "DOSEN", action: "grade:list", resourceType: "grade-list", condition: "CLASS_TEACHER" },
  { role: "DOSEN", action: "grade:update", resourceType: "grade", condition: "CLASS_TEACHER_MUTABLE" },
  { role: "DOSEN", action: "class:finalize", resourceType: "class", condition: "CLASS_TEACHER_FINALIZE" },
  { role: "ADMIN", action: "transcript:read", resourceType: "transcript", condition: "ADMIN" }
];

function deny(reasonCode: string): PolicyResult {
  return { decision: "DENY", reasonCode };
}

function allowed(): PolicyResult {
  return { decision: "ALLOW", reasonCode: "POLICY_ALLOW" };
}

function timeInWindow(currentTime: Date, window: AccessWindow): boolean | null {
  const timePattern = /^(?:[01]\d|2[0-3]):[0-5]\d$/u;
  if (
    !Number.isFinite(currentTime.getTime()) ||
    !timePattern.test(window.startTime) ||
    !timePattern.test(window.endTime) ||
    window.startTime === window.endTime
  ) {
    return null;
  }

  try {
    const parts = new Intl.DateTimeFormat("en-GB", {
      timeZone: window.timezone,
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23"
    }).formatToParts(currentTime);
    const hour = Number(parts.find((part) => part.type === "hour")?.value);
    const minute = Number(parts.find((part) => part.type === "minute")?.value);
    const currentMinutes = hour * 60 + minute;
    const [startHour, startMinute] = window.startTime.split(":").map(Number);
    const [endHour, endMinute] = window.endTime.split(":").map(Number);
    const startMinutes = (startHour ?? 0) * 60 + (startMinute ?? 0);
    const endMinutes = (endHour ?? 0) * 60 + (endMinute ?? 0);

    return startMinutes < endMinutes
      ? currentMinutes >= startMinutes && currentMinutes < endMinutes
      : currentMinutes >= startMinutes || currentMinutes < endMinutes;
  } catch {
    return null;
  }
}

export function evaluatePolicy(request: PolicyRequest): PolicyResult {
  const { subject, device, action, resource } = request;
  if (!subject.id || !["ADMIN", "DOSEN", "MAHASISWA"].includes(subject.role)) {
    return deny("INVALID_SUBJECT");
  }
  if (!subject.accountActive) return deny("ACCOUNT_INACTIVE");
  if (!device.id || !device.active) return deny("DEVICE_INACTIVE");
  if (device.userId !== subject.id) return deny("DEVICE_USER_MISMATCH");
  if (!resource.id || !resource.type) return deny("INVALID_RESOURCE");

  const matchingAction = RULES.filter(
    (rule) => rule.action === action && rule.resourceType === resource.type
  );
  if (matchingAction.length === 0) return deny("DEFAULT_DENY");

  const rule = matchingAction.find((candidate) => candidate.role === subject.role);
  if (!rule) return deny("ROLE_NOT_ALLOWED");

  switch (rule.condition) {
    case "OWNER":
      if (resource.ownerId !== subject.id) return deny("OWNERSHIP_MISMATCH");
      if (resource.classId && resource.enrolled !== true) return deny("STUDENT_NOT_ENROLLED");
      return allowed();
    case "CLASS_TEACHER":
      if (!resource.classId || resource.teacherId !== subject.id) {
        return deny("NOT_CLASS_LECTURER");
      }
      return allowed();
    case "CLASS_TEACHER_MUTABLE":
      if (!resource.classId || resource.teacherId !== subject.id) {
        return deny("NOT_CLASS_LECTURER");
      }
      if (resource.enrolled !== true) return deny("STUDENT_NOT_ENROLLED");
      if (resource.classFinalized !== false) return deny("CLASS_FINALIZED_OR_STATE_UNKNOWN");
      return checkAccessWindow(request.context);
    case "CLASS_TEACHER_FINALIZE":
      if (!resource.classId || resource.teacherId !== subject.id) return deny("NOT_CLASS_LECTURER");
      if (
        resource.classFinalized !== false &&
        resource.finalizationPending !== true &&
        resource.finalizationComplete !== true
      ) {
        return deny("CLASS_FINALIZED_OR_STATE_UNKNOWN");
      }
      return checkAccessWindow(request.context);
    case "ADMIN":
      return allowed();
  }
  return deny("DEFAULT_DENY");
}

function checkAccessWindow(context: PolicyContext | undefined): PolicyResult {
  const window = context?.accessWindow ?? DEFAULT_ACCESS_WINDOW;
  const now = context?.currentTime ?? new Date();
  const within = timeInWindow(now, window);
  if (within === null) return deny("INVALID_ACCESS_WINDOW");
  return within ? allowed() : deny("OUTSIDE_ACCESS_HOURS");
}
