CC       := gcc
CSTD     := -std=c11
WARN     := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wunused-parameter
OPT      := -O2
DEBUG    := -g

CFLAGS   := $(CSTD) $(WARN) $(OPT) $(DEBUG) -Iinclude -pthread
LDFLAGS  := -pthread

# Strict, MISRA-oriented profile used by `make misra`.
MISRA_CFLAGS := $(CSTD) $(WARN) -fanalyzer -Iinclude -pthread

SRC_DIR  := src
TEST_DIR := tests
OBJ_DIR  := build
TARGET   := bank

SOURCES     := $(wildcard $(SRC_DIR)/*.c)
OBJECTS     := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))
LIB_SOURCES := $(filter-out $(SRC_DIR)/main.c,$(SOURCES))

TEST_SOURCES := $(wildcard $(TEST_DIR)/*.c)
TEST_BIN     := test_runner

COVERAGE_DIR := $(OBJ_DIR)/coverage
COVERAGE_BIN := bank_coverage

.PHONY: all clean run dirs test smoke valgrind cppcheck misra coverage

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) database

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

run: all
	./$(TARGET)

# ============================================================
# UNIT / INTEGRATION TESTING
#
# No --coverage is used here.
# Therefore this target does not create .gcda/.gcno files.
# ============================================================

test: dirs
	@echo "=========================================="
	@echo " Running Unit / Integration Tests"
	@echo "=========================================="
	@rm -f $(TEST_BIN)
	@rm -rf database
	@mkdir -p database

	$(CC) $(CSTD) -Wall -Wextra -g -O0 \
		-Iinclude -I$(TEST_DIR) -pthread \
		$(LIB_SOURCES) $(TEST_SOURCES) \
		-o $(TEST_BIN) -lcunit -pthread

	./$(TEST_BIN)

	@rm -f $(TEST_BIN)
	@echo ""
	@echo "=========================================="
	@echo " Unit / Integration Tests Passed"
	@echo "=========================================="

# ============================================================
# SMOKE TEST
# ============================================================

smoke: all
	@rm -rf database
	./$(TARGET) < $(TEST_DIR)/smoke_input.txt
	@echo "Smoke test completed successfully."

# ============================================================
# VALGRIND
# ============================================================

valgrind:
	@mkdir -p database
	$(CC) $(CSTD) -Wall -Wextra -g -O0 \
		-Iinclude -pthread \
		$(LIB_SOURCES) $(SRC_DIR)/main.c \
		-o $(TARGET)_dbg -pthread
	@rm -rf database
	valgrind --leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--error-exitcode=99 \
		./$(TARGET)_dbg < $(TEST_DIR)/valgrind_input.txt

# ============================================================
# CPPCHECK
# ============================================================

cppcheck:
	cppcheck --enable=all \
		--std=c11 \
		--suppress=missingIncludeSystem \
		-Iinclude \
		$(SRC_DIR)

	cppcheck --enable=all \
		--std=c11 \
		--check-config \
		--suppress=missingIncludeSystem \
		-Iinclude \
		$(SRC_DIR)

# ============================================================
# MISRA-ORIENTED COMPILATION
# ============================================================

misra:
	$(CC) $(MISRA_CFLAGS) \
		$(SOURCES) \
		-o $(TARGET)_misra_check \
		-pthread

# ============================================================
# CODE COVERAGE
#
# Builds the CUnit test suite (every module under src/ except
# main.c, plus every tests/test_*.c) instrumented with
# --coverage, runs the full 89+ test suite, and reports
# per-function/branch coverage via gcov, plus an HTML report via
# lcov/genhtml when available.
#
# Driving the CUnit suite (rather than the interactive app via a
# canned stdin script) is what actually exercises the library
# code's error paths, validation branches, and edge cases -- the
# same 89 tests already relied on for correctness are reused here
# to measure coverage, so there is nothing new to keep in sync.
#
# Temporary .gcda/.gcno files are removed after the report; the
# .gcov per-file annotated source and the lcov HTML report (if
# generated) are kept under $(COVERAGE_DIR).
# ============================================================

coverage: dirs
	@echo "=========================================="
	@echo " Building Test Suite for Code Coverage"
	@echo "=========================================="

	@rm -rf $(COVERAGE_DIR)
	@mkdir -p $(COVERAGE_DIR)
	@rm -f $(TEST_BIN)
	@rm -f *.gcda *.gcno *.gcov
	@rm -rf database
	@mkdir -p database

	$(CC) $(CSTD) -Wall -Wextra -g -O0 \
		--coverage \
		-Iinclude -I$(TEST_DIR) -pthread \
		$(LIB_SOURCES) $(TEST_SOURCES) \
		-o $(TEST_BIN) -lcunit -pthread

	@echo ""
	@echo "=========================================="
	@echo " Running Test Suite for Code Coverage"
	@echo "=========================================="

	./$(TEST_BIN)

	@echo ""
	@echo "=========================================="
	@echo " Generating Coverage Report"
	@echo "=========================================="

	@for file in $(LIB_SOURCES); do \
		base=$$(basename "$$file" .c); \
		gcov -b -f -o "$(TEST_BIN)-$$base.gcda" "$$file" >> $(COVERAGE_DIR)/summary.txt 2>&1 || true; \
	done

	@mv -f *.gcov $(COVERAGE_DIR)/ 2>/dev/null || true

	@echo ""
	@echo "========== COVERAGE SUMMARY (per function) =========="
	@grep -E "^File|^Function|Lines executed|Branches executed|Taken at least once" \
		$(COVERAGE_DIR)/summary.txt || true

	@if command -v lcov >/dev/null 2>&1 && command -v genhtml >/dev/null 2>&1; then \
		echo ""; \
		echo "========== GENERATING HTML REPORT =========="; \
		lcov --capture --directory . --output-file $(COVERAGE_DIR)/coverage.info \
			--rc branch_coverage=1 --ignore-errors mismatch,negative,unused >/dev/null 2>&1 || true; \
		lcov --remove $(COVERAGE_DIR)/coverage.info '/usr/*' '*/tests/*' \
			--output-file $(COVERAGE_DIR)/coverage.info \
			--rc branch_coverage=1 --ignore-errors unused >/dev/null 2>&1 || true; \
		genhtml $(COVERAGE_DIR)/coverage.info --output-directory $(COVERAGE_DIR)/html \
			--branch-coverage >/dev/null 2>&1 || true; \
		if [ -f $(COVERAGE_DIR)/html/index.html ]; then \
			echo "HTML report: $(COVERAGE_DIR)/html/index.html"; \
		fi; \
	else \
		echo ""; \
		echo "(lcov/genhtml not found -- skipping HTML report; per-file .gcov"; \
		echo " annotated source in $(COVERAGE_DIR)/ and the summary above are"; \
		echo " still complete.)"; \
	fi

	@rm -f $(TEST_BIN)
	@rm -f *.gcda *.gcno
	@rm -rf database

	@echo ""
	@echo "Coverage report: $(COVERAGE_DIR)/summary.txt"
	@echo "Annotated sources: $(COVERAGE_DIR)/*.c.gcov"
	@echo "Temporary .gcda/.gcno files removed."


# ============================================================
# CLEAN
# ============================================================

clean:
	rm -rf $(OBJ_DIR) \
		$(TARGET) \
		$(TARGET)_dbg \
		$(TARGET)_misra_check \
		$(TEST_BIN) \
		$(COVERAGE_BIN) \
		database \
		*.gcda *.gcno *.gcov \
		$(SRC_DIR)/*.gcda \
		$(SRC_DIR)/*.gcno \
		$(SRC_DIR)/*.gcov
