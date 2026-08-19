# Byte-Sensitivity Map

Artifact: `basmos.bin` (sha256 `b1a359d217f1023d6084bd4d0e09c255d00df267498a0bf0f2521dbf6e36476a`).
Method: each byte flipped (XOR 0xFF), booted in QEMU, classified by
the observable contract (3/6/9 + running + heartbeat). Single run;
fixed timeouts.

| Class | Glyph | Bytes | Meaning |
|---|---|---:|---|
| DEAD | `#` | 214 | contract never completes or guest not running |
| ALTERED-VISIBLE | `~` | 27 | alive, but VGA bytes differ |
| ALTERED-TIMER | `%` | 2 | 3/6/9 intact but heartbeat frozen |
| INTACT | `.` | 269 | no observable effect |

```
payload: 292 bytes   (# dead  ~ altered  % timer-dead  . intact)

000 ####.######.#############..#####
032 ########################.###..##
064 #############################..#
096 #####.#.##########...#...##.....
128 .#.#.#.#.##############...##.###
160 ~~~#~~##~~~#.#.##~~##~~#######~.
192 #~~##~~#...#####.##%############
224 ####..##~#.##~~~~#~###~~####~###
256 ~%##..####..###...######..####.#
288 ####............................
320 ................................
352 ................................
384 ................................
416 ................................
448 ................................
480 ..............................##
```

## Payload by symbol

| Symbol | INTACT | ALTERED-VISIBLE | ALTERED-TIMER | DEAD |
|---|---:|---:|---:|---:|
| start | 2 | 0 | 0 | 20 |
| pm | 25 | 0 | 0 | 98 |
| t1frame | 4 | 0 | 0 | 8 |
| task0 | 1 | 8 | 0 | 8 |
| task1 | 2 | 9 | 0 | 15 |
| exception_handler | 3 | 0 | 0 | 0 |
| timer_handler | 1 | 0 | 1 | 9 |
| do_switch | 0 | 0 | 0 | 8 |
| sys_send | 3 | 5 | 0 | 12 |
| sys_recv | 0 | 5 | 1 | 12 |
| idtr | 2 | 0 | 0 | 4 |
| gdt | 8 | 0 | 0 | 14 |
| gdt_end | 0 | 0 | 0 | 0 |
| other_sp | 0 | 0 | 0 | 4 |

Padding (292..509) and the two signature bytes are outside the
payload table; all 218 padding bytes classify as INTACT and both
signature bytes as DEAD.
