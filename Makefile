PROJECT = ft_nmap
PROJECT_DIR = .

RM = /bin/rm



SRCS_DIR = $(PROJECT_DIR)/srcs
OBJS_DIR = $(PROJECT_DIR)/objs
INCS_DIR = $(PROJECT_DIR)/incs
DEPS_DIR = $(PROJECT_DIR)/deps

SOURCES =	main.c \
			cli.c

HEADER_FILES = cli.h 

SRCS = $(addprefix $(SRCS_DIR)/, $(SOURCES))

OBJS = $(patsubst $(SRCS_DIR)/%.c,$(OBJS_DIR)/%.o,$(patsubst $(SRCS_DIR)/%.s,$(OBJS_DIR)/%.o,$(SRCS)))
DEPS = $(patsubst $(SRCS_DIR)/%.c,$(DEPS_DIR)/%.d,$(patsubst $(SRCS_DIR)/%.s,$(DEPS_DIR)/%.d,$(SRCS)))
INCS = -I $(INCS_DIR)
INCS_FILES = $(addprefix $(INCS_DIR)/, $(HEADER_FILES))


FLAG_DEBUG			= -g -ggdb3
FLAG_WARNING		= -Wall -Wextra -Winline -Wformat
FLAG_DEPENDENCIES	= -MMD -MF $(patsubst $(SRCS_DIR)/%,$(DEPS_DIR)/%,./$(<:.c=.d))
FLAG_INCS			= -I $(INCS_DIR)
FLAGS				= $(FLAG_INCS) $(FLAG_DEPENDENCIES) $(FLAG_DEBUG) $(FLAG_WARNING)

$(PROJECT):  $(OBJS)
	@echo Building $(PROJECT)
	@$(CC) $(FLAG_WARNING) $(FLAG_DEBUG) $(OBJS) -o $@

$(OBJS_DIR)/%.o : $(SRCS_DIR)/%.c $(INCS_FILES)
	@echo "Compiling $(notdir $<)..."
	@mkdir -p $(dir $@)
	@mkdir -p $(patsubst $(OBJS_DIR)/%,$(DEPS_DIR)/%,$(dir ./$(@:.o=.d)))
	@$(CC) $(FLAGS) -c $< -o $@

all: $(PROJECT)

clean:
	@echo "Cleaning files..."
	@$(RM) -rf $(OBJS_DIR)
	@$(RM) -rf $(DEPS_DIR)

fclean: clean
	@echo "Cleaning build..."
	@$(RM) -f $(PROJECT)

re: fclean all

-include $(DEPS)

.PHONY: all clean fclean re
