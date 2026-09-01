# Makefile - Implementacion educativa de DES en C.
#
# Targets:
#   make            Compila la biblioteca, los tests y el ejemplo.
#   make test       Compila y ejecuta la suite de pruebas.
#   make examples   Compila y ejecuta el programa de demostracion.
#   make clean      Elimina todos los artefactos generados.
#
# Todo lo generado vive bajo build/, de modo que `make clean` nunca toca
# archivos fuente y el arbol de trabajo queda siempre limpio.

CC       ?= cc
CFLAGS   ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
CPPFLAGS += -Iinclude -MMD -MP
LDFLAGS  ?=

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin

# Fuentes del nucleo del algoritmo. Se listan de forma explicita en lugar de
# usar un wildcard: src/des_modes.c todavia no tiene implementacion y una
# unidad de traduccion vacia es un error bajo -Wpedantic. Se anadira a esta
# lista en el mismo commit en el que se implemente el primer modo.
LIB_SRCS := \
	src/des_tables.c \
	src/des_keyschedule.c \
	src/des_feistel.c \
	src/des.c

TEST_SRCS    := tests/test_des.c
EXAMPLE_SRCS := examples/main.c

LIB_OBJS     := $(LIB_SRCS:%.c=$(OBJ_DIR)/%.o)
TEST_OBJS    := $(TEST_SRCS:%.c=$(OBJ_DIR)/%.o)
EXAMPLE_OBJS := $(EXAMPLE_SRCS:%.c=$(OBJ_DIR)/%.o)

TEST_BIN    := $(BIN_DIR)/test_des
EXAMPLE_BIN := $(BIN_DIR)/des_demo

# Ficheros .d generados por -MMD: permiten que un cambio en una cabecera
# fuerce la recompilacion de los .c que la incluyen.
DEPS := $(LIB_OBJS:.o=.d) $(TEST_OBJS:.o=.d) $(EXAMPLE_OBJS:.o=.d)

.PHONY: all test examples clean help

all: $(TEST_BIN) $(EXAMPLE_BIN)

$(TEST_BIN): $(LIB_OBJS) $(TEST_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(EXAMPLE_BIN): $(LIB_OBJS) $(EXAMPLE_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test: $(TEST_BIN)
	@./$(TEST_BIN)

examples: $(EXAMPLE_BIN)
	@./$(EXAMPLE_BIN)

clean:
	$(RM) -r $(BUILD_DIR)

help:
	@echo "Targets disponibles:"
	@echo "  all       Compila tests y ejemplo (por defecto)."
	@echo "  test      Ejecuta la suite de pruebas."
	@echo "  examples  Ejecuta el programa de demostracion."
	@echo "  clean     Elimina el directorio build/."

-include $(DEPS)
