set pagination off
target remote :31504
break *Mal_func4+0x31
commands
 silent
 printf "\n[HIT] Mal_func4 before fork(), pc=%p counter=%d\n", $pc, *(int*)($ebp-0xc)
 printf "[SAFE] skip fork(), simulate parent path, advance loop counter\n"
 set *(int*)($ebp-0xc)=*(int*)($ebp-0xc)+1
 set $pc=$pc+5
 set $eax=1
 continue
end
continue

