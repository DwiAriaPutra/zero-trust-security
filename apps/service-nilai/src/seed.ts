import type { SqliteDatabase } from "@zero-trust/database";

interface DemoClass {
  id: string;
  name: string;
  lecturerId: string;
  term: string;
  scores: readonly [number, number, number];
}

const STUDENTS = [
  "demo-student-001",
  "demo-student-002",
  "demo-student-003"
] as const;

const CLASSES: readonly DemoClass[] = [
  {
    id: "demo-class-algoritma-2026",
    name: "Algoritma dan Struktur Data",
    lecturerId: "demo-lecturer-001",
    term: "2026-Ganjil",
    scores: [85, 91, 78]
  },
  {
    id: "demo-class-keamanan-2026",
    name: "Keamanan Informasi",
    lecturerId: "demo-lecturer-002",
    term: "2026-Ganjil",
    scores: [88, 82, 94]
  }
];

function assertDemoAccount(
  database: SqliteDatabase,
  id: string,
  role: "DOSEN" | "MAHASISWA"
): void {
  const user = database
    .prepare("SELECT role FROM users WHERE id = ?")
    .get(id) as { role: string } | undefined;
  if (user?.role !== role) {
    throw new Error(`Required local demo account is missing or has a different role: ${id}`);
  }
}

export function seedNilaiDemoData(database: SqliteDatabase): void {
  for (const lecturerId of ["demo-lecturer-001", "demo-lecturer-002"]) {
    assertDemoAccount(database, lecturerId, "DOSEN");
  }
  for (const studentId of STUDENTS) assertDemoAccount(database, studentId, "MAHASISWA");

  const seed = database.transaction(() => {
    const findClass = database.prepare("SELECT name, lecturer_id, term FROM classes WHERE id = ?");
    const insertClass = database.prepare(`
      INSERT OR IGNORE INTO classes (id, name, lecturer_id, term)
      VALUES (?, ?, ?, ?)
    `);
    const insertEnrollment = database.prepare(`
      INSERT OR IGNORE INTO enrollments (class_id, student_id)
      VALUES (?, ?)
    `);
    const insertGrade = database.prepare(`
      INSERT OR IGNORE INTO grades (class_id, student_id, score)
      VALUES (?, ?, ?)
    `);

    for (const course of CLASSES) {
      const existing = findClass.get(course.id) as
        | { name: string; lecturer_id: string; term: string }
        | undefined;
      if (
        existing &&
        (existing.name !== course.name ||
          existing.lecturer_id !== course.lecturerId ||
          existing.term !== course.term)
      ) {
        throw new Error(`Demo class conflicts with existing data: ${course.id}`);
      }
      insertClass.run(course.id, course.name, course.lecturerId, course.term);

      for (const [index, studentId] of STUDENTS.entries()) {
        insertEnrollment.run(course.id, studentId);
        insertGrade.run(course.id, studentId, course.scores[index] ?? 0);
      }
    }
  });
  seed();
}
