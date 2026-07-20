# bash completion for digg
_digg() {
    local cur="${COMP_WORDS[COMP_CWORD]}"

    local plus_flags="+short +json +yaml +tsv +compat +qr +noqr +stats +nostats \
+color +nocolor +tcp +notcp +recurse +norecurse +authority +noauthority \
+additional +noadditional +trace +dnssec +validate +cd +nocd +dot +edns +noedns +nsid \
+idnin +noidnin +idnout +noidnout +propagation +prop +bench +watch +doh \
+timeout= +retry= +bench= +watch= +doh= +subnet="
    local dash_flags="-x -p -c -f -h -V --help --version"
    local types="A AAAA NS CNAME PTR MX TXT SOA SRV DS RRSIG NSEC DNSKEY \
NSEC3 NSEC3PARAM CAA SVCB HTTPS AXFR ANY"
    local servers="@1.1.1.1 @8.8.8.8 @9.9.9.9"

    case "$cur" in
        +doh=*)
            COMPREPLY=($(compgen -W "+doh=cloudflare +doh=google +doh=quad9 +doh=opendns +doh=adguard +doh=wikimedia" -- "$cur"))
            return
            ;;
        +*)
            COMPREPLY=($(compgen -W "$plus_flags" -- "$cur"))
            compopt -o nospace 2>/dev/null
            return
            ;;
        @*)
            COMPREPLY=($(compgen -W "$servers" -- "$cur"))
            return
            ;;
        -*)
            COMPREPLY=($(compgen -W "$dash_flags" -- "$cur"))
            return
            ;;
    esac

    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        -c) COMPREPLY=($(compgen -W "IN CH HS ANY" -- "$cur")); return ;;
        -f) COMPREPLY=($(compgen -f -- "$cur")); return ;;
    esac

    COMPREPLY=($(compgen -W "$types" -- "$cur"))
}
complete -F _digg digg
