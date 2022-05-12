#include <aos/nameserver.h>
#include "nameserver_tests.h"

#define BEGIN_TESTS(name)                                                                \
    char *tests_name__ = name;                                                           \
    size_t tests_all__, tests_pass__, tests_fail__;                                      \
    tests_all__ = tests_pass__ = tests_fail__ = 0;                                       \
    DEBUG_PRINTF("running tests %s\n", name);

#define END_TESTS                                                                  \
    DEBUG_PRINTF("Summary of tests %s:\n\tpassed: %d of %d\n\tfailed: %d of %d\n",       \
                 tests_name__, tests_pass__, tests_all__, tests_fail__, tests_all__)

#define TEST(name, expr)                                                                 \
    tests_all__++;                                                                       \
    if (expr) {                                                                          \
        tests_pass__++;                                                                  \
    } else {                                                                             \
        tests_fail__++;                                                                  \
        DEBUG_PRINTF("Test %s failed\n", name);                                          \
    }

static void run_name_tests(void)
{
    BEGIN_TESTS("name_validity");
    TEST("a_invalid", !name_is_valid("a"));
    TEST("__invalid", !name_is_valid("_"));
    TEST("3_invalid", !name_is_valid("3"));
    TEST("ab_valid", name_is_valid("ab"));
    TEST("one.two", name_is_valid("one.two"));
    END_TESTS;
}

static void run_name_part_tests(void) {
    BEGIN_TESTS("name_parts");

    struct name_parts p;
    errval_t err = name_into_parts("\0", &p);

    TEST("null_invalid", err == LIB_ERR_NAMESERVICE_INVALID_NAME);

    err = name_into_parts("name", &p);

    TEST("single_is_success", err_is_ok(err));
    TEST("single_is_one", p.num_parts == 1);
    TEST("single_is_correct", strcmp("name", p.parts[0]) == 0);

    free(p.parts);

    err = name_into_parts("top.bot", &p);

    TEST("double_is_success", err_is_ok(err));
    TEST("double_is_two", p.num_parts == 2);
    TEST("double_first_is_top", strcmp("top", p.parts[0]) == 0);
    TEST("double_second_is_bot", strcmp("bot", p.parts[1]) == 0);

    free(p.parts);
    END_TESTS;
}

void run_nameserver_tests(void)
{
    run_name_tests();
    run_name_part_tests();
}