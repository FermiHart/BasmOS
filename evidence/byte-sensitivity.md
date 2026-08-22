# Byte-Sensitivity Map

Artifact: `basmos.bin` (sha256 `5b342405174202241bbc622d4fe1c94da367c8902f9a7a39cc9be211c79b74fe`).
Method: each byte flipped (XOR 0xFF), booted in QEMU, classified by
the observable contract. Single run; fixed timeouts.

| Class | Glyph | Bytes | Meaning |
|---|---|---:|---|
| DEAD | `#` | 281 | contract never completes or guest not running |
| ALTERED-VISIBLE | `~` | 33 | alive, but VGA bytes differ |
| ALTERED-TIMER | `%` | 3 | 3/6/9 intact but heartbeat frozen |
| INTACT | `.` | 195 | no observable effect |

```
payload: 401 bytes   (# dead  ~ altered  % timer-dead  . intact)

000 ####.######.#############..#####
032 ###########################..###
064 ..#####......###################
096 ##########..######.#.##########.
128 ..#...##......#.#.#..##########.
160 #######################...##.###
192 #..####.~~~~#~#~~###..###~~~#.##
224 ~##~~##~~~####.#..###~#~#~~###~#
256 ......#####%.##%###########.####
288 ##.##.###~#.###~~~~#~#####~#####
320 ~####~%##..####..###...######..#
352 ###.#....##.#....##.#..~~##.#..#
384 ###~#..##########...............
416 ................................
448 ................................
480 ..............................##
```

## Payload by symbol

| Symbol | INTACT | ALTERED-VISIBLE | ALTERED-TIMER | DEAD |
|---|---:|---:|---:|---:|
| start | 2 | 0 | 0 | 20 |
| pm | 33 | 0 | 0 | 122 |
| t1frame | 4 | 0 | 0 | 8 |
| task0 | 1 | 0 | 0 | 4 |
| task0_flat | 5 | 10 | 0 | 14 |
| task1 | 3 | 11 | 0 | 19 |
| exception_handler | 3 | 0 | 0 | 0 |
| gp_handler | 3 | 0 | 0 | 0 |
| timer_handler | 1 | 0 | 2 | 9 |
| do_switch | 1 | 0 | 0 | 10 |
| sys_send | 3 | 5 | 0 | 15 |
| sys_recv | 0 | 4 | 1 | 16 |
| idtr | 2 | 0 | 0 | 4 |
| gdt | 25 | 3 | 0 | 34 |
| other_sp | 0 | 0 | 0 | 4 |

Padding (401..509) and the two signature bytes are outside the
payload table; 109 padding bytes classify as INTACT and the
signature bytes classify as 2/2 DEAD.
