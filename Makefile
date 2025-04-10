PROJECT = ft_nmap
PROJECT_DIR = .

RM = rm

SRCS_DIR = $(PROJECT_DIR)/srcs
OBJS_DIR = $(PROJECT_DIR)/objs
INCS_DIR = $(PROJECT_DIR)/incs
DEPS_DIR = $(PROJECT_DIR)/deps

SOURCES =	main.c \
			pool.c \
			packet/packet.c \
			packet/tcp.c \
			packet/udp.c \
			packet/icmp.c \
			cli/cli.c \
			cli/utils.c \
			cli/params/file.c \
			cli/params/help.c \
			cli/params/ip.c \
			cli/params/port.c \
			cli/params/scan.c \
			cli/params/output_format.c \
			cli/params/speedup.c \
			queue/add.c \
			queue/count.c \
			queue/destroy.c \
			queue/find.c \
			queue/init.c \
			queue/print.c \
			queue/remove.c

HEADER_FILES = 	cli.h \
				cli_utils.h \
				packet.h \
				pool.h \
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
	@echo "Compiling $(notdir $<)..."
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
