#
# Copyright (c) 2023, Red Hat, Inc.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

NAME     := alt-java
SRC_DIR  := src
BIN_DIR  := bin
TEST_DIR := $(BIN_DIR)/test

CC     = gcc
CFLAGS = -pedantic -Wall -Wextra -Wconversion


.PHONY: all
all: build test


.PHONY: build
build: $(BIN_DIR)/$(NAME)
$(BIN_DIR)/$(NAME): $(SRC_DIR)/$(NAME).c
	mkdir -p $(BIN_DIR) && $(CC) $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.PHONY: rebuild
rebuild: clean build


.PHONY: test
test: $(TEST_DIR)
$(TEST_DIR): $(SRC_DIR)/test.sh $(BIN_DIR)/$(NAME)
	rm -rf $@ && mkdir -p $@ && cd $@ && bash $(addprefix ../../,$^) "$(JAVA_PATH)"

.PHONY: clean-test
clean-test:
	rm -rf $(TEST_DIR)

.PHONY: retest
retest: clean-test test
