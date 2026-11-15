/* Section edit fixture: one function, alone in its object's code section, so
   that -add-symbol can alias it at offset 0 of that section. Compiled with
   debug data, which section edits remove; that data and the unwind data
   describe the function, so removing its code section is refused. */
long bao_symedit_section(void) { return 7; }
