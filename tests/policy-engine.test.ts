import assert from "node:assert/strict";
import test from "node:test";
import { evaluatePolicy, type PolicyRequest } from "../packages/policy-engine/src/index.js";

const studentRequest: PolicyRequest = {
  subject: { id: "student-001", role: "MAHASISWA", accountActive: true },
  device: { id: "device-student-001", userId: "student-001", active: true },
  action: "grade:read",
  resource: {
    type: "grade",
    id: "grade-001",
    ownerId: "student-001",
    classId: "class-001",
    enrolled: true
  },
  context: { currentTime: new Date("2026-01-01T05:00:00.000Z") }
};

test("policy engine allows a matching explicit ownership policy", () => {
  assert.deepEqual(evaluatePolicy(studentRequest), {
    decision: "ALLOW",
    reasonCode: "POLICY_ALLOW"
  });
});

test("policy engine denies a finalized class mutation", () => {
  const request: PolicyRequest = {
    subject: { id: "lecturer-001", role: "DOSEN", accountActive: true },
    device: { id: "device-lecturer-001", userId: "lecturer-001", active: true },
    action: "grade:update",
    resource: {
      type: "grade",
      id: "grade-001",
      classId: "class-001",
      teacherId: "lecturer-001",
      enrolled: true,
      classFinalized: true
    },
    context: { currentTime: new Date("2026-01-01T05:00:00.000Z") }
  };
  assert.equal(evaluatePolicy(request).reasonCode, "CLASS_FINALIZED_OR_STATE_UNKNOWN");
});

test("policy engine uses default deny when no action-resource policy exists", () => {
  assert.equal(
    evaluatePolicy({ ...studentRequest, action: "grade:delete" }).reasonCode,
    "DEFAULT_DENY"
  );
});

test("policy engine rejects a role with no explicit grant for the action", () => {
  const request: PolicyRequest = {
    ...studentRequest,
    action: "grade:update"
  };
  assert.equal(evaluatePolicy(request).reasonCode, "ROLE_NOT_ALLOWED");
});

test("policy engine rejects data owned by a different student", () => {
  const request: PolicyRequest = {
    ...studentRequest,
    resource: { ...studentRequest.resource, ownerId: "student-002" }
  };
  assert.equal(evaluatePolicy(request).reasonCode, "OWNERSHIP_MISMATCH");
});

test("policy engine rejects student access without a verified enrollment", () => {
  const request: PolicyRequest = {
    ...studentRequest,
    resource: { ...studentRequest.resource, enrolled: false }
  };
  assert.equal(evaluatePolicy(request).reasonCode, "STUDENT_NOT_ENROLLED");
});

test("policy engine rejects a device that is inactive or belongs to another user", () => {
  assert.equal(
    evaluatePolicy({ ...studentRequest, device: { ...studentRequest.device, active: false } }).reasonCode,
    "DEVICE_INACTIVE"
  );
  assert.equal(
    evaluatePolicy({ ...studentRequest, device: { ...studentRequest.device, userId: "student-002" } }).reasonCode,
    "DEVICE_USER_MISMATCH"
  );
});

test("policy engine enforces the configured Asia/Jakarta access window at its boundaries", () => {
  const mutableClassRequest: PolicyRequest = {
    subject: { id: "lecturer-001", role: "DOSEN", accountActive: true },
    device: { id: "device-lecturer-001", userId: "lecturer-001", active: true },
    action: "class:finalize",
    resource: {
      type: "class",
      id: "class-001",
      classId: "class-001",
      teacherId: "lecturer-001",
      classFinalized: false
    }
  };
  const atOpening = evaluatePolicy({
    ...mutableClassRequest,
    context: { currentTime: new Date("2026-01-01T00:00:00.000Z") }
  });
  const beforeClosing = evaluatePolicy({
    ...mutableClassRequest,
    context: { currentTime: new Date("2026-01-01T13:59:59.000Z") }
  });
  const atClosing = evaluatePolicy({
    ...mutableClassRequest,
    context: { currentTime: new Date("2026-01-01T14:00:00.000Z") }
  });

  assert.equal(atOpening.decision, "ALLOW");
  assert.equal(beforeClosing.decision, "ALLOW");
  assert.equal(atClosing.reasonCode, "OUTSIDE_ACCESS_HOURS");
});

test("lecturer access requires the lecturer assigned to the class", () => {
  const request: PolicyRequest = {
    subject: { id: "lecturer-001", role: "DOSEN", accountActive: true },
    device: { id: "device-lecturer-001", userId: "lecturer-001", active: true },
    action: "grade:read",
    resource: {
      type: "grade",
      id: "grade-001",
      classId: "class-001",
      teacherId: "lecturer-002"
    }
  };
  assert.equal(evaluatePolicy(request).reasonCode, "NOT_CLASS_LECTURER");
});




