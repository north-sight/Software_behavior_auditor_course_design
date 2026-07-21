set pagination off
target remote :31502
break *Mal_func2+0x27
commands
 silent
 printf "\n[HIT] Mal_func2 before rename(), pc=%p\n", $pc
 printf "rename old path: "
 x/s *(char**)$esp
 printf "rename new path: "
 x/s *(char**)($esp+4)
 printf "[SAFE] skip rename() and force success for next checks\n"
 set $esp=$esp+8
 set $pc=$pc+5
 set $eax=0
 continue
end
break *Mal_func2+0x46
commands
 silent
 printf "\n[HIT] Mal_func2 before chmod(), pc=%p\n", $pc
 printf "chmod path: "
 x/s *(char**)$esp
 printf "chmod mode: 0%o\n", *(int*)($esp+4)
 printf "[SAFE] skip chmod() and force success for system() branch\n"
 set $esp=$esp+8
 set $pc=$pc+5
 set $eax=0
 continue
end
break *Mal_func2+0x6e
commands
 silent
 printf "\n[HIT] Mal_func2 before system(), pc=%p\n", $pc
 printf "system argument: "
 x/s *(char**)$esp
 printf "[SAFE] skip system('./system.sh')\n"
 set $esp=$esp+4
 set $pc=$pc+5
 set $eax=-1
 continue
end
continue

