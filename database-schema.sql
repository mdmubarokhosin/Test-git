-- ============================================================================
-- Madrasa Result Portal CMS - PostgreSQL Database Schema
-- Created: 2026-01-05 06:32:08 UTC
-- Description: Complete database schema for managing Madrasa (Islamic School)
--              results, students, courses, and administrative functions
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. USERS & AUTHENTICATION TABLES
-- ============================================================================

-- Users table for authentication and role management
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    date_of_birth DATE,
    gender VARCHAR(10),
    profile_picture_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- User roles table
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    UNIQUE(user_id, role),
    CONSTRAINT check_valid_role CHECK (role IN ('admin', 'teacher', 'student', 'parent', 'accountant', 'principal', 'vice_principal', 'moderator'))
);

-- User permissions table
CREATE TABLE IF NOT EXISTS user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(100) NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by UUID REFERENCES users(id),
    UNIQUE(user_id, permission)
);

-- ============================================================================
-- 2. ORGANIZATION & INSTITUTION TABLES
-- ============================================================================

-- Academic institutions (Madrasas)
CREATE TABLE IF NOT EXISTS institutions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    registration_number VARCHAR(100) UNIQUE,
    code VARCHAR(50) UNIQUE NOT NULL,
    address TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state_province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    email VARCHAR(255),
    website_url TEXT,
    principal_name VARCHAR(200),
    establishment_year INTEGER,
    total_students INTEGER DEFAULT 0,
    total_teachers INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    logo_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Departments within institution
CREATE TABLE IF NOT EXISTS departments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) NOT NULL,
    department_head_id UUID REFERENCES users(id),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, code)
);

-- ============================================================================
-- 3. ACADEMIC STRUCTURE TABLES
-- ============================================================================

-- Academic years/Sessions
CREATE TABLE IF NOT EXISTS academic_years (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    year_name VARCHAR(50) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    is_current BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, year_name)
);

-- Classes/Grades/Sections
CREATE TABLE IF NOT EXISTS classes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    department_id UUID REFERENCES departments(id),
    class_name VARCHAR(100) NOT NULL,
    class_code VARCHAR(50) NOT NULL,
    level INTEGER NOT NULL,
    class_teacher_id UUID REFERENCES users(id),
    capacity INTEGER DEFAULT 40,
    total_students INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, class_code)
);

-- Subjects offered
CREATE TABLE IF NOT EXISTS subjects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    subject_name VARCHAR(255) NOT NULL,
    subject_code VARCHAR(50) NOT NULL,
    description TEXT,
    credit_hours INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, subject_code)
);

-- Class Subject Mapping (which subjects are taught in which classes)
CREATE TABLE IF NOT EXISTS class_subjects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    teacher_id UUID REFERENCES users(id),
    total_marks INTEGER DEFAULT 100,
    passing_marks INTEGER DEFAULT 40,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(class_id, subject_id)
);

-- ============================================================================
-- 4. STUDENT & ENROLLMENT TABLES
-- ============================================================================

-- Students
CREATE TABLE IF NOT EXISTS students (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    registration_number VARCHAR(100) UNIQUE NOT NULL,
    roll_number VARCHAR(50),
    date_of_birth DATE NOT NULL,
    gender VARCHAR(10) NOT NULL,
    blood_group VARCHAR(5),
    father_name VARCHAR(200) NOT NULL,
    father_phone VARCHAR(20),
    mother_name VARCHAR(200),
    mother_phone VARCHAR(20),
    emergency_contact_name VARCHAR(200),
    emergency_contact_phone VARCHAR(20),
    residential_address TEXT,
    permanent_address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    admission_date DATE NOT NULL,
    scholarship_status VARCHAR(50),
    scholarship_percentage DECIMAL(5, 2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Student enrollment in classes (for academic year)
CREATE TABLE IF NOT EXISTS student_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    enrollment_date DATE DEFAULT CURRENT_DATE,
    status VARCHAR(20) DEFAULT 'active',
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, class_id, academic_year_id)
);

-- ============================================================================
-- 5. TEACHER & STAFF TABLES
-- ============================================================================

-- Teachers
CREATE TABLE IF NOT EXISTS teachers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    employee_id VARCHAR(100) UNIQUE NOT NULL,
    qualification VARCHAR(500),
    specialization VARCHAR(255),
    date_of_joining DATE NOT NULL,
    date_of_birth DATE,
    gender VARCHAR(10),
    phone_number VARCHAR(20),
    address TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    employment_type VARCHAR(50),
    salary_grade VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Teacher assignments to classes
CREATE TABLE IF NOT EXISTS teacher_class_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    teacher_id UUID NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    is_class_teacher BOOLEAN DEFAULT FALSE,
    assigned_date DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 6. EXAMINATION & RESULTS TABLES
-- ============================================================================

-- Examination types
CREATE TABLE IF NOT EXISTS examination_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    type_name VARCHAR(100) NOT NULL,
    type_code VARCHAR(50) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, type_code)
);

-- Examinations
CREATE TABLE IF NOT EXISTS examinations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    examination_type_id UUID NOT NULL REFERENCES examination_types(id) ON DELETE CASCADE,
    exam_date DATE NOT NULL,
    exam_time TIME,
    duration_minutes INTEGER,
    total_marks INTEGER DEFAULT 100,
    passing_marks INTEGER DEFAULT 40,
    exam_name VARCHAR(255),
    description TEXT,
    is_published BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Student exam results
CREATE TABLE IF NOT EXISTS exam_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    examination_id UUID NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    marks_obtained DECIMAL(6, 2),
    percentage DECIMAL(5, 2),
    grade_point DECIMAL(4, 2),
    grade VARCHAR(2),
    status VARCHAR(20),
    is_passed BOOLEAN,
    remarks TEXT,
    recorded_by UUID REFERENCES users(id),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    UNIQUE(examination_id, student_id)
);

-- Grading scale
CREATE TABLE IF NOT EXISTS grading_scales (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    grade_name VARCHAR(2) NOT NULL,
    min_percentage DECIMAL(5, 2) NOT NULL,
    max_percentage DECIMAL(5, 2) NOT NULL,
    grade_point DECIMAL(4, 2),
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, grade_name)
);

-- ============================================================================
-- 7. ATTENDANCE TABLES
-- ============================================================================

-- Student attendance
CREATE TABLE IF NOT EXISTS student_attendance (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    attendance_date DATE NOT NULL,
    is_present BOOLEAN NOT NULL,
    marked_by UUID REFERENCES users(id),
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_id, class_id, attendance_date)
);

-- ============================================================================
-- 8. FEES & PAYMENTS TABLES
-- ============================================================================

-- Fee structure
CREATE TABLE IF NOT EXISTS fee_structures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    fee_type VARCHAR(100) NOT NULL,
    amount DECIMAL(12, 2) NOT NULL,
    due_date DATE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Student fee records
CREATE TABLE IF NOT EXISTS student_fees (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    academic_year_id UUID NOT NULL REFERENCES academic_years(id) ON DELETE CASCADE,
    fee_structure_id UUID REFERENCES fee_structures(id),
    total_amount DECIMAL(12, 2) NOT NULL,
    amount_paid DECIMAL(12, 2) DEFAULT 0,
    amount_due DECIMAL(12, 2),
    due_date DATE,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fee payments
CREATE TABLE IF NOT EXISTS fee_payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_fee_id UUID NOT NULL REFERENCES student_fees(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    payment_amount DECIMAL(12, 2) NOT NULL,
    payment_date DATE DEFAULT CURRENT_DATE,
    payment_method VARCHAR(50),
    transaction_id VARCHAR(100),
    receipt_number VARCHAR(100) UNIQUE,
    remarks TEXT,
    processed_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(student_fee_id, transaction_id)
);

-- ============================================================================
-- 9. RESULT PUBLISHING & ANNOUNCEMENTS
-- ============================================================================

-- Result publishing settings
CREATE TABLE IF NOT EXISTS result_publishing (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    examination_type_id UUID REFERENCES examination_types(id),
    academic_year_id UUID REFERENCES academic_years(id),
    is_published BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP,
    published_by UUID REFERENCES users(id),
    announcement_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Announcements
CREATE TABLE IF NOT EXISTS announcements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    announcement_type VARCHAR(50),
    target_audience VARCHAR(100),
    is_published BOOLEAN DEFAULT FALSE,
    published_date TIMESTAMP,
    expiry_date TIMESTAMP,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

-- ============================================================================
-- 10. AUDIT & LOGGING TABLES
-- ============================================================================

-- Activity logs
CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID REFERENCES institutions(id),
    user_id UUID REFERENCES users(id),
    action_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    description TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs for sensitive changes
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID REFERENCES institutions(id),
    user_id UUID REFERENCES users(id),
    table_name VARCHAR(100) NOT NULL,
    record_id UUID,
    action VARCHAR(20) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    change_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 11. NOTIFICATIONS & MESSAGING
-- ============================================================================

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID REFERENCES institutions(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id),
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    notification_type VARCHAR(50),
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- ============================================================================
-- 12. DOCUMENTS & CERTIFICATES
-- ============================================================================

-- Document templates
CREATE TABLE IF NOT EXISTS document_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    template_name VARCHAR(255) NOT NULL,
    template_type VARCHAR(100),
    content TEXT,
    file_path TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Generated certificates
CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    student_id UUID NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    certificate_type VARCHAR(100),
    academic_year_id UUID REFERENCES academic_years(id),
    certificate_number VARCHAR(100) UNIQUE,
    issue_date DATE DEFAULT CURRENT_DATE,
    file_path TEXT,
    is_issued BOOLEAN DEFAULT FALSE,
    issued_at TIMESTAMP,
    issued_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 13. SETTINGS & CONFIGURATION
-- ============================================================================

-- Institution settings
CREATE TABLE IF NOT EXISTS institution_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    institution_id UUID NOT NULL UNIQUE REFERENCES institutions(id) ON DELETE CASCADE,
    setting_key VARCHAR(255) NOT NULL,
    setting_value TEXT,
    setting_type VARCHAR(50),
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(institution_id, setting_key)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================================

-- User indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role);

-- Institution indexes
CREATE INDEX idx_institutions_code ON institutions(code);
CREATE INDEX idx_institutions_is_active ON institutions(is_active);
CREATE INDEX idx_departments_institution_id ON departments(institution_id);
CREATE INDEX idx_departments_code ON departments(code);

-- Academic structure indexes
CREATE INDEX idx_academic_years_institution_id ON academic_years(institution_id);
CREATE INDEX idx_academic_years_is_current ON academic_years(is_current);
CREATE INDEX idx_classes_institution_id ON classes(institution_id);
CREATE INDEX idx_classes_class_code ON classes(class_code);
CREATE INDEX idx_subjects_institution_id ON subjects(institution_id);
CREATE INDEX idx_class_subjects_class_id ON class_subjects(class_id);
CREATE INDEX idx_class_subjects_subject_id ON class_subjects(subject_id);
CREATE INDEX idx_class_subjects_teacher_id ON class_subjects(teacher_id);

-- Student indexes
CREATE INDEX idx_students_institution_id ON students(institution_id);
CREATE INDEX idx_students_registration_number ON students(registration_number);
CREATE INDEX idx_students_is_active ON students(is_active);
CREATE INDEX idx_student_enrollments_student_id ON student_enrollments(student_id);
CREATE INDEX idx_student_enrollments_class_id ON student_enrollments(class_id);
CREATE INDEX idx_student_enrollments_academic_year_id ON student_enrollments(academic_year_id);

-- Teacher indexes
CREATE INDEX idx_teachers_institution_id ON teachers(institution_id);
CREATE INDEX idx_teachers_employee_id ON teachers(employee_id);
CREATE INDEX idx_teachers_is_active ON teachers(is_active);
CREATE INDEX idx_teacher_class_assignments_teacher_id ON teacher_class_assignments(teacher_id);
CREATE INDEX idx_teacher_class_assignments_class_id ON teacher_class_assignments(class_id);

-- Examination indexes
CREATE INDEX idx_examinations_institution_id ON examinations(institution_id);
CREATE INDEX idx_examinations_academic_year_id ON examinations(academic_year_id);
CREATE INDEX idx_examinations_class_id ON examinations(class_id);
CREATE INDEX idx_examinations_exam_date ON examinations(exam_date);
CREATE INDEX idx_exam_results_examination_id ON exam_results(examination_id);
CREATE INDEX idx_exam_results_student_id ON exam_results(student_id);
CREATE INDEX idx_exam_results_grade ON exam_results(grade);

-- Attendance indexes
CREATE INDEX idx_student_attendance_student_id ON student_attendance(student_id);
CREATE INDEX idx_student_attendance_class_id ON student_attendance(class_id);
CREATE INDEX idx_student_attendance_date ON student_attendance(attendance_date);

-- Fee indexes
CREATE INDEX idx_fee_structures_institution_id ON fee_structures(institution_id);
CREATE INDEX idx_fee_structures_class_id ON fee_structures(class_id);
CREATE INDEX idx_student_fees_student_id ON student_fees(student_id);
CREATE INDEX idx_student_fees_status ON student_fees(status);
CREATE INDEX idx_fee_payments_student_id ON fee_payments(student_id);
CREATE INDEX idx_fee_payments_payment_date ON fee_payments(payment_date);

-- Announcement indexes
CREATE INDEX idx_announcements_institution_id ON announcements(institution_id);
CREATE INDEX idx_announcements_is_published ON announcements(is_published);

-- Logging indexes
CREATE INDEX idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX idx_activity_logs_created_at ON activity_logs(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_table_name ON audit_logs(table_name);

-- Notification indexes
CREATE INDEX idx_notifications_recipient_id ON notifications(recipient_id);
CREATE INDEX idx_notifications_is_read ON notifications(is_read);

-- Certificate indexes
CREATE INDEX idx_certificates_student_id ON certificates(student_id);
CREATE INDEX idx_certificates_institution_id ON certificates(institution_id);

-- ============================================================================
-- CONSTRAINTS & TRIGGERS
-- ============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update timestamp trigger to users table
CREATE TRIGGER trigger_users_update
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Apply update timestamp trigger to institutions table
CREATE TRIGGER trigger_institutions_update
BEFORE UPDATE ON institutions
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Apply update timestamp trigger to students table
CREATE TRIGGER trigger_students_update
BEFORE UPDATE ON students
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Apply update timestamp trigger to exam_results table
CREATE TRIGGER trigger_exam_results_update
BEFORE UPDATE ON exam_results
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- ============================================================================
-- VIEW: Student Transcript
-- ============================================================================
CREATE OR REPLACE VIEW vw_student_transcripts AS
SELECT 
    s.id AS student_id,
    s.registration_number,
    u.first_name || ' ' || u.last_name AS student_name,
    ay.year_name AS academic_year,
    c.class_name,
    sub.subject_name,
    er.marks_obtained,
    er.percentage,
    er.grade,
    er.status,
    i.name AS institution_name
FROM students s
JOIN users u ON s.user_id = u.id
JOIN student_enrollments se ON s.id = se.student_id
JOIN academic_years ay ON se.academic_year_id = ay.id
JOIN classes c ON se.class_id = c.id
JOIN institutions i ON s.institution_id = i.id
LEFT JOIN examinations e ON c.id = e.class_id AND ay.id = e.academic_year_id
LEFT JOIN exam_results er ON e.id = er.examination_id AND s.id = er.student_id
LEFT JOIN subjects sub ON e.subject_id = sub.id
ORDER BY ay.year_name DESC, c.level DESC, sub.subject_name;

-- ============================================================================
-- VIEW: Class Performance Report
-- ============================================================================
CREATE OR REPLACE VIEW vw_class_performance AS
SELECT 
    c.id AS class_id,
    c.class_name,
    sub.subject_name,
    COUNT(DISTINCT er.student_id) AS total_students_appeared,
    COUNT(DISTINCT CASE WHEN er.is_passed THEN er.student_id END) AS total_passed,
    COUNT(DISTINCT CASE WHEN NOT er.is_passed THEN er.student_id END) AS total_failed,
    ROUND(AVG(er.percentage)::numeric, 2) AS average_percentage,
    MAX(er.marks_obtained) AS highest_marks,
    MIN(er.marks_obtained) AS lowest_marks
FROM classes c
JOIN class_subjects cs ON c.id = cs.class_id
JOIN subjects sub ON cs.subject_id = sub.id
LEFT JOIN examinations e ON c.id = e.class_id AND cs.subject_id = e.subject_id
LEFT JOIN exam_results er ON e.id = er.examination_id
GROUP BY c.id, c.class_name, sub.id, sub.subject_name
ORDER BY c.class_name, sub.subject_name;

-- ============================================================================
-- VIEW: Student Financial Status
-- ============================================================================
CREATE OR REPLACE VIEW vw_student_financial_status AS
SELECT 
    s.id AS student_id,
    s.registration_number,
    u.first_name || ' ' || u.last_name AS student_name,
    ay.year_name,
    sf.total_amount,
    COALESCE(sf.amount_paid, 0) AS amount_paid,
    sf.amount_due,
    sf.status,
    sf.due_date,
    i.name AS institution_name
FROM students s
JOIN users u ON s.user_id = u.id
JOIN student_fees sf ON s.id = sf.student_id
JOIN academic_years ay ON sf.academic_year_id = ay.id
JOIN institutions i ON s.institution_id = i.id
ORDER BY s.registration_number, ay.year_name DESC;

-- ============================================================================
-- VIEW: Attendance Summary
-- ============================================================================
CREATE OR REPLACE VIEW vw_attendance_summary AS
SELECT 
    s.id AS student_id,
    s.registration_number,
    u.first_name || ' ' || u.last_name AS student_name,
    c.class_name,
    COUNT(*) AS total_days,
    COUNT(CASE WHEN sa.is_present THEN 1 END) AS days_present,
    COUNT(CASE WHEN NOT sa.is_present THEN 1 END) AS days_absent,
    ROUND(
        (COUNT(CASE WHEN sa.is_present THEN 1 END)::numeric / COUNT(*)) * 100, 
        2
    ) AS attendance_percentage
FROM students s
JOIN users u ON s.user_id = u.id
JOIN student_attendance sa ON s.id = sa.student_id
JOIN classes c ON sa.class_id = c.id
GROUP BY s.id, s.registration_number, u.first_name, u.last_name, c.id, c.class_name
ORDER BY s.registration_number, c.class_name;

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================
