PROJECT = ft_nmap
PROJECT_DIR = .

RM = rm

SRCS_DIR = $(PROJECT_DIR)/srcs
OBJS_DIR = $(PROJECT_DIR)/objs
INCS_DIR = $(PROJECT_DIR)/incs
DEPS_DIR = $(PROJECT_DIR)/deps


SRC_CLI_PARAMS = \
	file.c \
	help.c \
	ip.c \
	output_format.c \
	port.c \
	scan.c \
	speedup.c

SRC_CLI = \
	$(addprefix params/, $(SRC_CLI_PARAMS)) \
	cli.c \
	utils.c

SRC_PACKET_CAPTURE_INFO = \
	eth_info.c \
	icmp_info.c \
	ip_info.c \
	tcp_info.c \
	udp_info.c

SRC_PACKET_CAPTURE_LISTENER = \
	icmp.c \
	tcp.c \
	udp.c

SRC_PACKET_CAPTURE_UTILS = \
	print.c

SRC_PACKET_CAPTURE = \
	$(addprefix info/, $(SRC_PACKET_CAPTURE_INFO)) \
	$(addprefix listener/, $(SRC_PACKET_CAPTURE_LISTENER)) \
	$(addprefix utils/, $(SRC_PACKET_CAPTURE_UTILS)) \
	packet.c \
	packet_capture.c


SRC_POOL_UTILS = \
	print.c \
	task.c

SRC_POOL = \
	$(addprefix utils/, $(SRC_POOL_UTILS)) \
	pool.c \
	send.c

SRC_SCAN_TYPE_UTILS = \
	checksum.c \
	header_builds.c \
	packet_switch.c \
	print.c

SRC_SCAN_TYPE_PACKET = \
	ack.c \
	fin.c \
	null.c \
	syn.c \
	upd.c \
	xmas.c

SRC_SCAN_TYPE = \
	$(addprefix utils/, $(SRC_SCAN_TYPE_UTILS)) \
	$(addprefix packet/, $(SRC_SCAN_TYPE_PACKET)) \

SRC_UTILS_QUEUE = \
	add.c \
	count.c \
	destroy.c \
	find.c \
	init.c \
	print.c \
	remove.c

SRC_UTILS = \
	$(addprefix queue/, $(SRC_UTILS_QUEUE))

SOURCES = \
	$(addprefix cli/, $(SRC_CLI)) \
	$(addprefix packet_capture/, $(SRC_PACKET_CAPTURE)) \
	$(addprefix pool/, $(SRC_POOL)) \
	$(addprefix scan_type/, $(SRC_SCAN_TYPE)) \
	$(addprefix utils/, $(SRC_UTILS)) \
	main.c \
	
# xmas.c

OBJECTS := $(SOURCES:.c=.o)

HEADERS = \
	cli.h \
	cli_utils.h \
	packet.h \
	pool.h \
	scan_type.h \
	packet/header.h \
	packet/checksum.h \
	packet/scan_type.h \
	queue.h


SRCS = $(addprefix $(SRCS_DIR)/, $(SOURCES))
OBJS = $(addprefix $(OBJS_DIR)/, $(OBJECTS))
INCS = $(addprefix $(INCS_DIR)/, $(HEADERS))

DEPS = $(patsubst $(SRCS_DIR)/%.c,$(DEPS_DIR)/%.d,$(patsubst $(SRCS_DIR)/%.s,$(DEPS_DIR)/%.d,$(SRCS)))

FLAG_DEBUG			= -g -ggdb3
FLAG_WARNING		= -Wall -Wextra -Winline -Wformat
FLAG_DEPENDENCIES	= -MMD -MF $(patsubst $(SRCS_DIR)/%,$(DEPS_DIR)/%,./$(<:.c=.d))
FLAG_INCS			= -I $(INCS_DIR)
FLAG_LIBS			= -lpthread -lpcap
FLAGS				= $(FLAG_INCS) $(FLAG_DEPENDENCIES) $(FLAG_DEBUG) $(FLAG_WARNING)

gg: 
	@echo $(OBJS)

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

test:
	valgrind \
		--leak-check=full \
		./ft_nmap --ports 80 --ip 127.56.0.1 --scan ACK SYN

-include $(DEPS)

.PHONY: all clean fclean re
