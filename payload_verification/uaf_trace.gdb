set pagination off
target remote :31508
break *Vul_func3+0x8a
commands
 silent
 printf "\n[HIT] Vul_func3 before free(), pc=%p\n", $pc
 printf "free pointer: %p\n", *(void**)$esp
 continue
end
break *Vul_func3+0x9d
commands
 silent
 printf "\n[HIT] Vul_func3 before mprotect(PROT_NONE), pc=%p\n", $pc
 printf "mprotect addr=%p len=%d prot=%d\n", *(void**)$esp, *(int*)($esp+4), *(int*)($esp+8)
 continue
end
continue

