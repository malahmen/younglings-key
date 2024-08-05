#re_subject='(\/)(CN|O|OU|C|ST|L|E|Serial Number|Validity Period|Key Usage|Extended Key Usage|Subject Alternative Name|Issuer|Signature Algorithm|Public Key)(?:\=.+)'

re_subject='^/C=[A-Z]{2}/ST=[^/=]*/L=[^/=]*/CN=[^/=]+/O=[^/=]+(/OU=[^/=]*)?$'
