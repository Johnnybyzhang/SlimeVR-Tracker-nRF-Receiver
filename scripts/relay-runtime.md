# Runtime relay settings

Production defaults are 11 members, static R5, 16 ticks, minimum 100 TPS and cap 120 TPS. The repair floor equals the ceiling. Editing max_repairs while equal keeps both equal, including zero and later increases. Geometry capacity clamps both together. A floor above a newly lowered ceiling clamps to that ceiling. A lower floor otherwise remains an explicit experimental demand choice.

`relay layout repair_floor 0` opts into experimental on-demand repair. Phase 2 found saturation at R5 and worse equal-R coverage on the eleven-tracker fleet. Restore static mode with `relay layout repair_floor 5` at ceiling 5. Settings persist in NVS and activate through the existing staged publication. Version-1 static NVS records load with floor equal to ceiling. Version-2 records preserve an explicit demand setting.
