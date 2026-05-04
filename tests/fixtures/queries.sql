-- Ad hoc patient lookup for John Doe, MRN 12345678
SELECT first_name, last_name, dob
FROM patients
WHERE ssn = '123-45-6789';

/* Adjust billing on card 4111-1111-1111-1111 */
UPDATE billing
SET card = '4111-1111-1111-1111'
WHERE email = 'jane.s@example.org';

INSERT INTO visits (patient_id, note) VALUES ('P001', 'Called patient at (415) 555-0199.');
