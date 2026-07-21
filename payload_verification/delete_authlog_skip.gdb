set pagination off
target remote :31501
break *Mal_func1+0x32
commands
 silent
 printf "\n[HIT] Mal_func1 before remove(), pc=%p\n", $pc
 printf "remove argument: "
 x/s *(char**)$esp
 printf "[SAFE] skip remove('/var/log/auth.log')\n"
 set $esp=$esp+4
 set $pc=$pc+5
 set $eax=-1
 continue
end
continue

