PROJECT = ft_nmap
PROJECT_DIR = .

RM = rm

SRCS_DIR = $(PROJECT_DIR)/srcs
OBJS_DIR = $(PROJECT_DIR)/objs
INCS_DIR = $(PROJECT_DIR)/incs
DEPS_DIR = $(PROJECT_DIR)/deps

SRC_CLI_PARAMS = $(addprefix params/, \
			file.c \
			help.c \
			ip.c \
			port.c \
			scan.c \
			output_format.c \
			speedup.c)

SRC_CLI = $(addprefix cli/, \
	$(SRC_CLI_PARAMS) \
	cli.c \
	utils.c)

SRC_PACKET_GENERATOR_CHECKSUM = $(addprefix checksum/, \
			ip.c \
			tcp.c)

SRC_PACKET_GENERATOR_HEADER = $(addprefix header/, \
			ip.c \
			tcp.c)

SRC_PACKET_GENERATOR_SCAN_TYPE = $(addprefix scan_type/, \
		ack.c \
		fin.c \
		null.c \
		syn.c \
		upd.c \
		xmas.c)

SRC_PACKET_GENERATOR = $(addprefix generator/, \
	$(SRC_PACKET_GENERATOR_CHECKSUM) \
	$(SRC_PACKET_GENERATOR_HEADER) \
	$(SRC_PACKET_GENERATOR_SCAN_TYPE) \
	pool.c)

SRC_PACKET_LISTENER = $(addprefix listener/, \
			packet.c \
			listener.c \
			tcp.c \
			udp.c \
			icmp.c)

SRC_PACKET = $(addprefix packet/, \
	$(SRC_PACKET_GENERATOR) \
	$(SRC_PACKET_LISTENER))

SRC_QUEUE = $(addprefix queue/, \
			add.c \
			count.c \
			destroy.c \
			find.c \
			init.c \
			print.c \
			remove.c )

SOURCES =	main.c \
			$(SRC_QUEUE) \
			$(SRC_PACKET) \
			$(SRC_CLI)

HEADER_FILES = 	cli.h \
				cli_utils.h \
				packet.h \
				pool.h \
				scan_type.h \
				packet/header.h \
				packet/checksum.h \
				packet/scan_type.h \
				queue.h

SRCS = $(addprefix $(SRCS_DIR)/, $(SOURCES))

OBJS = $(patsubst $(SRCS_DIR)/%.c,$(OBJS_DIR)/%.o,$(patsubst $(SRCS_DIR)/%.s,$(OBJS_DIR)/%.o,$(SRCS)))
DEPS = $(patsubst $(SRCS_DIR)/%.c,$(DEPS_DIR)/%.d,$(patsubst $(SRCS_DIR)/%.s,$(DEPS_DIR)/%.d,$(SRCS)))
INCS = -I $(INCS_DIR)
INCS_FILES = $(addprefix $(INCS_DIR)/, $(HEADER_FILES))


FLAG_DEBUG			= -g -ggdb3
FLAG_WARNING		= -Wall -Wextra -Winline -Wformat
FLAG_DEPENDENCIES	= -MMD -MF $(patsubst $(SRCS_DIR)/%,$(DEPS_DIR)/%,./$(<:.c=.d))
FLAG_INCS			= -I $(INCS_DIR)
FLAG_LIBS			= -lpthread -lpcap
FLAGS				= $(FLAG_INCS) $(FLAG_DEPENDENCIES) $(FLAG_DEBUG) $(FLAG_WARNING)

all: $(PROJECT)
	@if echo $$SHELL | grep "zsh" > /dev/null 2>&1; then \
		echo "\033[1;37mFor autocompletion please run:\033[0m"; \
		echo "	fpath+=$$(pwd)"; \
		echo "	autoload -U compinit && compinit"; \
	fi
	
$(PROJECT): $(OBJS)
	@echo Building $(PROJECT)
	@$(CC) $(FLAG_WARNING) $(FLAG_DEBUG) $(OBJS) -o $@ $(FLAG_LIBS)

$(OBJS_DIR)/%.o : $(SRCS_DIR)/%.c $(INCS_FILES)
	@mkdir -p $(dir $@)
	@mkdir -p $(patsubst $(OBJS_DIR)/%,$(DEPS_DIR)/%,$(dir ./$(@:.o=.d)))
	@$(CC) $(FLAGS) -c $< -o $@

clean:
	@echo "Cleaning files..."
	@$(RM) -rf $(OBJS_DIR)
	@$(RM) -rf $(DEPS_DIR)

fclean: clean
	@echo "Cleaning build..."
	@$(RM) -f $(PROJECT)

re: fclean all

vagrant:
	@vagrant up
	@echo "Please add this setting to your ~/.ssh/config"
	@vagrant ssh-config

-include $(DEPS)

.PHONY: all clean fclean re
