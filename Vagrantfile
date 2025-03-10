Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"  # Ubuntu 20.04 LTS

  # Sync local source code directory to /vagrant_data in the VM
  config.vm.synced_folder ".", "/home/vagrant/project"

  config.vm.provision "shell", inline: <<-SHELL
    sudo apt update
    sudo apt install -y libpcap-dev build-essential
  SHELL

  config.vm.network "private_network", type: "dhcp"
end
