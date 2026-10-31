import type Database from "better-sqlite3";
import { hashPassword, type UserRole } from "./index.js";

export interface DemoAccount {
  id: string;
  email: string;
  password: string;
  role: UserRole;
  deviceId: string;
}

export const DEMO_ACCOUNTS: readonly DemoAccount[] = [
  {
    id: "demo-admin-001",
    email: "admin.demo@zero-trust.local",
    password: "AdminDemo-Local-2026!",
    role: "ADMIN",
    deviceId: "demo-device-admin-001"
  },
  {
    id: "demo-lecturer-001",
    email: "dosen1.demo@zero-trust.local",
    password: "Dosen1Demo-Local-2026!",
    role: "DOSEN",
    deviceId: "demo-device-dosen1-001"
  },
  {
    id: "demo-lecturer-002",
    email: "dosen2.demo@zero-trust.local",
    password: "Dosen2Demo-Local-2026!",
    role: "DOSEN",
    deviceId: "demo-device-dosen2-001"
  },
  {
    id: "demo-student-001",
    email: "mahasiswa1.demo@zero-trust.local",
    password: "Mhs1Demo-Local-2026!",
    role: "MAHASISWA",
    deviceId: "demo-device-mhs1-001"
  },
  {
    id: "demo-student-002",
    email: "mahasiswa2.demo@zero-trust.local",
    password: "Mhs2Demo-Local-2026!",
    role: "MAHASISWA",
    deviceId: "demo-device-mhs2-001"
  },
  {
    id: "demo-student-003",
    email: "mahasiswa3.demo@zero-trust.local",
    password: "Mhs3Demo-Local-2026!",
    role: "MAHASISWA",
    deviceId: "demo-device-mhs3-001"
  }
];

interface PreparedAccount extends DemoAccount {
  passwordHash: string;
}

export async function seedDemoAccounts(database: Database.Database): Promise<void> {
  const findUser = database.prepare("SELECT id, email, role FROM users WHERE id = ? OR email = ?");
  const findDevice = database.prepare("SELECT user_id FROM devices WHERE id = ?");
  const prepared: PreparedAccount[] = [];

  for (const account of DEMO_ACCOUNTS) {
    const existing = findUser.get(account.id, account.email) as
      | { id: string; email: string; role: UserRole }
      | undefined;
    if (existing) {
      if (
        existing.id !== account.id ||
        existing.email.toLowerCase() !== account.email ||
        existing.role !== account.role
      ) {
        throw new Error(`Demo account identity conflicts with existing data: ${account.email}`);
      }
      prepared.push({ ...account, passwordHash: "" });
      continue;
    }
    prepared.push({ ...account, passwordHash: await hashPassword(account.password) });
  }

  const seed = database.transaction(() => {
    for (const account of prepared) {
      const device = findDevice.get(account.deviceId) as { user_id: string } | undefined;
      if (device && device.user_id !== account.id) {
        throw new Error(`Demo device ID belongs to a different account: ${account.deviceId}`);
      }

      if (account.passwordHash) {
        database
          .prepare(`
            INSERT INTO users (id, email, password_hash, role, nim)
            VALUES (?, ?, ?, ?, ?)
          `)
          .run(
            account.id,
            account.email,
            account.passwordHash,
            account.role,
            account.role === "MAHASISWA" ? account.id : null
          );
      } else if (account.role === "MAHASISWA") {
        database.prepare("UPDATE users SET nim = id WHERE id = ? AND nim IS NULL")
          .run(account.id);
      }

      database
        .prepare("INSERT OR IGNORE INTO devices (id, user_id) VALUES (?, ?)")
        .run(account.deviceId, account.id);
    }
  });
  seed();
}
