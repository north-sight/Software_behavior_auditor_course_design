set pagination off
target remote :31509
break *Vul_func45+0x56
commands
 silent
 printf "\n[HIT] Vul_func45 before malloc(), pc=%p\n", $pc
 printf "malloc size argument: %u\n", *(unsigned int*)$esp
 continue
end
break *Vul_func45+0xa2
commands
 silent
 printf "\n[HIT] Vul_func45 before out-of-bounds write, pc=%p\n", $pc
 printf "base ptr=%p target ptr=%p offset=0xf0000000\n", *(void**)($ebp-0x14), $eax
 continue
end
continue

