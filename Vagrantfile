Vagrant.configure("2") do |config|
  config.ssh.keep_alive = true
  
  config.vm.box = "ubuntu/focal64"  # Ubuntu 20.04 LTS
  config.vm.hostname = "nmap-dev"
  
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "nmap-dev-vm"  # Better VM name in VirtualBox GUI
  end
  
  config.vm.network "forwarded_port", guest: 22, host: 2222, id: "ssh", auto_correct: true
  
  NMAP_PROJECT_DIR = "/home/vagrant/nmap-project"
  ZSH_THEME = "agnoster"  # Default theme

  config.vm.provision "shell", inline: <<-SHELL
    # Update system and install dependencies
    apt-get update
    apt-get upgrade -y
    # Provisioning for C development
    apt-get install -y git gdb valgrind make clang libpcap-dev

    # Network tools (for testing/reference)
    apt-get install -y nmap netcat tcpdump iputils-ping

    # Shell environment setup
    apt-get install -y zsh curl
    chsh -s $(which zsh) vagrant
    
    # Install oh-my-zsh AS VAGRANT USER  non-interactively
    sudo -u vagrant sh -c 'RUNZSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"'
    sudo -u vagrant sh -c 'sed -i "s/^ZSH_THEME=.*/ZSH_THEME=\"#{ZSH_THEME}\"/" ~/.zshrc'

    # Create project directory
    mkdir -p #{NMAP_PROJECT_DIR}
    chown vagrant:vagrant #{NMAP_PROJECT_DIR}
    
    # Install VS Code server dependencies
    apt-get install -y wget tar openssh-server
  SHELL

  # Sync current directory to the project directory
  config.vm.synced_folder ".", NMAP_PROJECT_DIR, owner: "vagrant", group: "vagrant"
end