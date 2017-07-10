curl -o bird https://github.com/projectcalico/bird/releases/download/v0.3.1/bird
curl -o felix https://github.com/projectcalico/felix/releases/download/2.3.0/calico-felix
curl -o calico https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/calico
curl -o calico-ipam https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/calico-ipam
curl -o portmap https://github.com/projectcalico/cni-plugin/releases/download/v1.9.1/portmap


tar cvfz calico-cni-1.9.tar.gz calico calico-ipam portmap
tar cvfz bird-1.6.3-1.tar.gz bird
tar cvfz calico-felix-2.3.0.tar.gz felix


bosh add-blob bird-1.6.3-1.tar.gz bird/bird-1.6.3-1.tar.gz 
bosh add-blob calico-felix-2.3.0.tar.gz calico/calico-felix-2.3.0.tar.gz 
bosh add-blob calico-cni-1.9.tar.gz calico-cni/calico-cni-1.9.tar.gz

bosh upload-blobs
