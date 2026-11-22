/* 검사 루틴을 고정 VA(0x600000)에 평탄 배치하기 위한 링커 스크립트.
 * VRewriter 가 이 블롭을 바이너리의 새 실행 세그먼트(0x600000)에 그대로 주입한다.
 * 모든 절대 참조(문자열 리터럴 등)가 0x600000 기준으로 해소되도록 한 섹션에 모은다. */
ENTRY(__vtint_check)
SECTIONS
{
  . = 0x600000;
  .blob : {
    *(.text)
    *(.text.*)
    *(.rodata)
    *(.rodata.*)
    *(.data)
    *(.data.*)
  }
  /DISCARD/ : { *(.note.*) *(.comment) *(.eh_frame) *(.eh_frame_hdr) }
}
