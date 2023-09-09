ALTER TABLE pacientes ADD activo TINYINT;
UPDATE pacientes SET activo = 1;

