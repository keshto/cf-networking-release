curl -o bird -L https://github.com/projectcalico/bird/releases/download/v0.3.1/bird
curl -o bird6 -L https://github.com/projectcalico/bird/releases/download/v0.3.1/bird6
curl -o birdcl -L https://github.com/projectcalico/bird/releases/download/v0.3.1/birdcl
curl -o felix -L https://github.com/projectcalico/felix/releases/download/2.3.0/calico-felix
curl -o calico -L https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/calico
curl -o calico-ipam -L https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/calico-ipam
curl -o portmap -L https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/portmap
curl -o confd -L https://github.com/kelseyhightower/confd/releases/download/v0.11.0/confd-0.11.0-linux-amd64

curl -o ipset_6.20.1-1_amd64.deb -L http://mirrors.kernel.org/ubuntu/pool/universe/i/ipset/ipset_6.20.1-1_amd64.deb
curl -o libipset3_6.20.1-1_amd64.deb -L http://mirrors.kernel.org/ubuntu/pool/universe/i/ipset/libipset3_6.20.1-1_amd64.deb
curl -o libmnl0_1.0.3-3ubuntu1_amd64.deb -L http://mirrors.kernel.org/ubuntu/pool/main/libm/libmnl/libmnl0_1.0.3-3ubuntu1_amd64.deb

tar cvfz calico-cni-1.9.tar.gz calico calico-ipam portmap
tar cvfz bird-1.6.3-1.tar.gz bird*
tar cvfz calico-felix-2.3.0.tar.gz felix
tar cvfz confd-0.11.0.tar.gz confd

tar cvfz ipset.tar.gz *.deb


bosh add-blob bird-1.6.3-1.tar.gz bird/bird-1.6.3-1.tar.gz 
bosh add-blob calico-felix-2.3.0.tar.gz calico/calico-felix-2.3.0.tar.gz 
bosh add-blob calico-cni-1.9.tar.gz calico-cni/calico-cni-1.9.tar.gz
bosh add-blob confd-0.11.0.tar.gz confd/confd-0.11.0.tar.gz

bosh add-blob ipset.tar.gz ipset/ipset.tar.gz

bosh upload-blobs
