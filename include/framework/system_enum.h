//
// Created by Administrator on 10/10/2023.
//

#ifndef GGADV_INCLUDE_FRAMEWORK_SYSTEM_ENUM_H_
#define GGADV_INCLUDE_FRAMEWORK_SYSTEM_ENUM_H_

constexpr static double USEC_PER_SECOND = 1000000.0;
constexpr static double USEC_PER_CYCLE = USEC_PER_SECOND / 16780000;
constexpr static unsigned CYCLE_PER_DOT = 4;

constexpr static unsigned LINE_PER_VISIBLE_SCREEN = 160;
constexpr static unsigned LINE_PER_VBLANK_INTERVAL = 68;

constexpr static unsigned DOT_PER_VISIBLE_SCANLINE = 240;
constexpr static unsigned DOT_PER_HBLANK_INTERVAL = 68;
constexpr static unsigned DOT_PER_SCANLINE = DOT_PER_VISIBLE_SCANLINE + DOT_PER_HBLANK_INTERVAL;

constexpr static unsigned CYCLE_PER_SCANLINE = DOT_PER_SCANLINE * CYCLE_PER_DOT;

// According GBATEK(LCD I/O Interrupts and status chapter), H-Blank flag remain 0 for 1006 cycles.
constexpr static unsigned CYCLE_PER_VISIBLE_SCANLINE = 1006;

// 1232 - 1006 = 226
// Note that although there are 68 dots in H-Blank interval, the H-Blank flag remain 0 for 1006 cycles.
// So the actual H-Blank interval is 226 cycles.(Not 68*4 = 272 cycles)
constexpr static unsigned CYCLE_PER_HBLANK_INTERVAL = CYCLE_PER_SCANLINE - CYCLE_PER_VISIBLE_SCANLINE;

constexpr static unsigned CYCLE_PER_FRAME = CYCLE_PER_SCANLINE * (LINE_PER_VISIBLE_SCREEN + LINE_PER_VBLANK_INTERVAL);

enum class E_SYSTEM_STATE {
  NORMAL,
  H_BLANK,
  V_BLANK
};

#endif //GGADV_INCLUDE_FRAMEWORK_SYSTEM_ENUM_H_
