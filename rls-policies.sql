-- ============================================================================
-- Row Level Security (RLS) Policies
-- Comprehensive RLS setup for multi-role access control
-- Admin (full access), Teacher (institution-scoped), Student (self-only),
-- Parent (student-related access)
-- ============================================================================

-- ============================================================================
-- 1. ENABLE ROW LEVEL SECURITY ON ALL TABLES
-- ============================================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE institutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE parents ENABLE ROW LEVEL SECURITY;
ALTER TABLE courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE grades ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
ALTER TABLE announcements ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 2. USERS TABLE POLICIES
-- ============================================================================

-- Admin: Full access to all users
CREATE POLICY admin_users_full_access ON users
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view users in their institution
CREATE POLICY teacher_users_view ON users
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM teachers t
      WHERE t.user_id = auth.uid()
      AND (
        t.institution_id = (SELECT institution_id FROM teachers WHERE user_id = users.id LIMIT 1)
        OR users.role = 'admin'
      )
    )
  );

-- Student: Can view own profile and other students in their class
CREATE POLICY student_users_view ON users
  FOR SELECT
  USING (
    id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM students s1
      WHERE s1.user_id = auth.uid()
      AND EXISTS (
        SELECT 1 FROM students s2
        WHERE s2.user_id = users.id
        AND s2.class_id = s1.class_id
      )
    )
  );

-- Parent: Can view student and own profile
CREATE POLICY parent_users_view ON users
  FOR SELECT
  USING (
    id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM parents p
      WHERE p.user_id = auth.uid()
      AND EXISTS (
        SELECT 1 FROM students s
        WHERE s.user_id = users.id
        AND s.id = ANY(p.student_ids)
      )
    )
  );

-- Self update policy
CREATE POLICY user_update_self ON users
  FOR UPDATE
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

-- ============================================================================
-- 3. INSTITUTIONS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_institutions_full_access ON institutions
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view only their institution
CREATE POLICY teacher_institutions_view ON institutions
  FOR SELECT
  USING (
    id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Student: Can view their institution
CREATE POLICY student_institutions_view ON institutions
  FOR SELECT
  USING (
    id = (
      SELECT DISTINCT t.institution_id
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.user_id = auth.uid()
      LIMIT 1
    )
  );

-- Parent: Can view child's institution
CREATE POLICY parent_institutions_view ON institutions
  FOR SELECT
  USING (
    id = (
      SELECT DISTINCT t.institution_id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE p.user_id = auth.uid()
      LIMIT 1
    )
  );

-- ============================================================================
-- 4. CLASSES TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_classes_full_access ON classes
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view classes in their institution
CREATE POLICY teacher_classes_view ON classes
  FOR SELECT
  USING (
    institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Teacher: Can update their classes
CREATE POLICY teacher_classes_update ON classes
  FOR UPDATE
  USING (
    institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  )
  WITH CHECK (
    institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Student: Can view their class
CREATE POLICY student_classes_view ON classes
  FOR SELECT
  USING (
    id = (SELECT class_id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Parent: Can view child's class
CREATE POLICY parent_classes_view ON classes
  FOR SELECT
  USING (
    id IN (
      SELECT DISTINCT c.id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      JOIN classes c ON s.class_id = c.id
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 5. STUDENTS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_students_full_access ON students
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view students in their institution's classes
CREATE POLICY teacher_students_view ON students
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM classes c
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE c.id = students.class_id
      AND t.user_id = auth.uid()
    )
  );

-- Student: Can view self and classmates
CREATE POLICY student_students_view ON students
  FOR SELECT
  USING (
    user_id = auth.uid()
    OR class_id = (SELECT class_id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Student: Can update own profile
CREATE POLICY student_students_update ON students
  FOR UPDATE
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Parent: Can view assigned students
CREATE POLICY parent_students_view ON students
  FOR SELECT
  USING (
    id IN (
      SELECT UNNEST(student_ids)
      FROM parents
      WHERE user_id = auth.uid()
    )
  );

-- ============================================================================
-- 6. TEACHERS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_teachers_full_access ON teachers
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view self and other teachers in same institution
CREATE POLICY teacher_teachers_view ON teachers
  FOR SELECT
  USING (
    user_id = auth.uid()
    OR institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Teacher: Can update self
CREATE POLICY teacher_teachers_update ON teachers
  FOR UPDATE
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Student: Can view their teachers
CREATE POLICY student_teachers_view ON teachers
  FOR SELECT
  USING (
    institution_id IN (
      SELECT DISTINCT t.institution_id
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.user_id = auth.uid()
    )
  );

-- Parent: Can view child's teachers
CREATE POLICY parent_teachers_view ON teachers
  FOR SELECT
  USING (
    institution_id IN (
      SELECT DISTINCT t.institution_id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 7. PARENTS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_parents_full_access ON parents
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Parent: Can view self
CREATE POLICY parent_parents_view ON parents
  FOR SELECT
  USING (user_id = auth.uid());

-- Parent: Can update self
CREATE POLICY parent_parents_update ON parents
  FOR UPDATE
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Teacher: Can view parents of students in their classes
CREATE POLICY teacher_parents_view ON teachers
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE t.user_id = auth.uid()
      AND s.id = ANY(parents.student_ids)
    )
  );

-- ============================================================================
-- 8. COURSES TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_courses_full_access ON courses
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view and manage courses they teach
CREATE POLICY teacher_courses_view ON courses
  FOR SELECT
  USING (
    teacher_id = (SELECT id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
    OR institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Teacher: Can update their courses
CREATE POLICY teacher_courses_update ON courses
  FOR UPDATE
  USING (
    teacher_id = (SELECT id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  )
  WITH CHECK (
    teacher_id = (SELECT id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
  );

-- Student: Can view courses in their class
CREATE POLICY student_courses_view ON courses
  FOR SELECT
  USING (
    class_id = (SELECT class_id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Parent: Can view child's courses
CREATE POLICY parent_courses_view ON courses
  FOR SELECT
  USING (
    class_id IN (
      SELECT DISTINCT s.class_id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 9. ENROLLMENTS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_enrollments_full_access ON enrollments
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view enrollments in their courses
CREATE POLICY teacher_enrollments_view ON enrollments
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = enrollments.course_id
      AND t.user_id = auth.uid()
    )
  );

-- Student: Can view their enrollments
CREATE POLICY student_enrollments_view ON enrollments
  FOR SELECT
  USING (
    student_id = (SELECT id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Parent: Can view child's enrollments
CREATE POLICY parent_enrollments_view ON enrollments
  FOR SELECT
  USING (
    student_id IN (
      SELECT s.id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 10. ASSIGNMENTS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_assignments_full_access ON assignments
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view, create, and update assignments in their courses
CREATE POLICY teacher_assignments_view ON assignments
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = assignments.course_id
      AND t.user_id = auth.uid()
    )
  );

CREATE POLICY teacher_assignments_insert ON assignments
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = assignments.course_id
      AND t.user_id = auth.uid()
    )
  );

CREATE POLICY teacher_assignments_update ON assignments
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = assignments.course_id
      AND t.user_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = assignments.course_id
      AND t.user_id = auth.uid()
    )
  );

-- Student: Can view assignments for their courses
CREATE POLICY student_assignments_view ON assignments
  FOR SELECT
  USING (
    course_id IN (
      SELECT c.id
      FROM courses c
      JOIN enrollments e ON c.id = e.course_id
      JOIN students s ON e.student_id = s.id
      WHERE s.user_id = auth.uid()
    )
  );

-- Parent: Can view child's assignments
CREATE POLICY parent_assignments_view ON assignments
  FOR SELECT
  USING (
    course_id IN (
      SELECT DISTINCT c.id
      FROM courses c
      JOIN enrollments e ON c.id = e.course_id
      JOIN students s ON e.student_id = s.id
      JOIN parents p ON s.id = ANY(p.student_ids)
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 11. GRADES TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_grades_full_access ON grades
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view and update grades for their students
CREATE POLICY teacher_grades_view ON grades
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = grades.course_id
      AND t.user_id = auth.uid()
    )
  );

CREATE POLICY teacher_grades_update ON grades
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = grades.course_id
      AND t.user_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM courses c
      JOIN teachers t ON c.teacher_id = t.id
      WHERE c.id = grades.course_id
      AND t.user_id = auth.uid()
    )
  );

-- Student: Can view their own grades
CREATE POLICY student_grades_view ON grades
  FOR SELECT
  USING (
    student_id = (SELECT id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Parent: Can view child's grades
CREATE POLICY parent_grades_view ON grades
  FOR SELECT
  USING (
    student_id IN (
      SELECT s.id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 12. ATTENDANCE TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_attendance_full_access ON attendance
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view and record attendance for their classes
CREATE POLICY teacher_attendance_view ON attendance
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.id = attendance.student_id
      AND t.user_id = auth.uid()
    )
  );

CREATE POLICY teacher_attendance_insert ON attendance
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.id = attendance.student_id
      AND t.user_id = auth.uid()
    )
  );

CREATE POLICY teacher_attendance_update ON attendance
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.id = attendance.student_id
      AND t.user_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.id = attendance.student_id
      AND t.user_id = auth.uid()
    )
  );

-- Student: Can view own attendance
CREATE POLICY student_attendance_view ON attendance
  FOR SELECT
  USING (
    student_id = (SELECT id FROM students WHERE user_id = auth.uid() LIMIT 1)
  );

-- Parent: Can view child's attendance
CREATE POLICY parent_attendance_view ON attendance
  FOR SELECT
  USING (
    student_id IN (
      SELECT s.id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- 13. ANNOUNCEMENTS TABLE POLICIES
-- ============================================================================

-- Admin: Full access
CREATE POLICY admin_announcements_full_access ON announcements
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM users u
      WHERE u.id = auth.uid()
      AND u.role = 'admin'
    )
  );

-- Teacher: Can view announcements and create for their institution
CREATE POLICY teacher_announcements_view ON announcements
  FOR SELECT
  USING (
    institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
    OR created_by = auth.uid()
  );

CREATE POLICY teacher_announcements_insert ON announcements
  FOR INSERT
  WITH CHECK (
    institution_id = (SELECT institution_id FROM teachers WHERE user_id = auth.uid() LIMIT 1)
    AND created_by = auth.uid()
  );

CREATE POLICY teacher_announcements_update ON announcements
  FOR UPDATE
  USING (created_by = auth.uid())
  WITH CHECK (created_by = auth.uid());

-- Student: Can view announcements for their institution
CREATE POLICY student_announcements_view ON announcements
  FOR SELECT
  USING (
    institution_id IN (
      SELECT DISTINCT t.institution_id
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE s.user_id = auth.uid()
    )
  );

-- Parent: Can view announcements for child's institution
CREATE POLICY parent_announcements_view ON announcements
  FOR SELECT
  USING (
    institution_id IN (
      SELECT DISTINCT t.institution_id
      FROM parents p
      JOIN students s ON s.id = ANY(p.student_ids)
      JOIN classes c ON s.class_id = c.id
      JOIN teachers t ON c.institution_id = t.institution_id
      WHERE p.user_id = auth.uid()
    )
  );

-- ============================================================================
-- SUMMARY OF RLS POLICIES
-- ============================================================================
/*
ADMIN:
  - Full unrestricted access to all tables
  - Can perform all CRUD operations on all entities

TEACHER:
  - Institution-scoped access
  - Can view and manage users, classes, and courses within their institution
  - Can record and manage student grades and attendance
  - Can create and manage assignments
  - Can view parent information for their students
  - Cannot access data from other institutions

STUDENT:
  - Self-only and class-scoped access
  - Can view own profile and update self
  - Can view classmates
  - Can view courses and assignments for their classes
  - Can view own grades and attendance
  - Cannot view other students' grades or attendance outside their class
  - Cannot modify grades or attendance

PARENT:
  - Student-related access
  - Can view assigned students and related institutions
  - Can view student grades, attendance, and assignments
  - Can view announcements from child's institution
  - Can view teachers and classes related to their students
  - Limited to viewing only assigned student information

AUTHORIZATION HIERARCHY:
  Admin > Teacher > Student/Parent
*/

-- ============================================================================
-- END OF RLS POLICIES
-- ============================================================================
