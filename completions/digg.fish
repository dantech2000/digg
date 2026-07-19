# fish completion for digg
complete -c digg -f

# +options
for flag in short json yaml tsv compat qr noqr stats nostats color nocolor \
    tcp notcp recurse norecurse authority noauthority additional noadditional \
    trace dnssec dot edns noedns nsid idnin noidnin idnout noidnout \
    propagation prop bench watch doh
    complete -c digg -a "+$flag"
end
for flag in timeout retry bench watch subnet
    complete -c digg -a "+$flag="
end
for provider in cloudflare google quad9 opendns adguard wikimedia
    complete -c digg -a "+doh=$provider"
end

# record types
complete -c digg -a "A AAAA NS CNAME PTR MX TXT SOA SRV DS RRSIG NSEC DNSKEY NSEC3 NSEC3PARAM CAA SVCB HTTPS AXFR ANY"

# well-known resolvers
complete -c digg -a "@1.1.1.1 @8.8.8.8 @9.9.9.9"

# dash flags
complete -c digg -s x -d "Reverse DNS lookup" -x
complete -c digg -s p -d "Server port" -x
complete -c digg -s c -d "Query class" -xa "IN CH HS ANY"
complete -c digg -s f -d "Batch file" -r
complete -c digg -s h -l help -d "Show help"
complete -c digg -s V -l version -d "Show version"
