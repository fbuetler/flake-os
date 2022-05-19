#include <aos/nameserver.h>
#include <spawn/spawn.h>
#include "test.h"
#include "server.h"
#include "name_tree.h"
#include "proc_mgmt.h"

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

#define TEST_ERR(name, expr)                                                                 \
    tests_all__++;                                                                       \
    if (expr) {                                                                          \
        tests_pass__++;                                                                  \
    } else {                                                                             \
        tests_fail__++;                                                                  \
        DEBUG_ERR(err, "Test %s failed\n", name);                                          \
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

    TEST_ERR("null_invalid", err == LIB_ERR_NAMESERVICE_INVALID_NAME);

    err = name_into_parts("name", &p);

    TEST_ERR("single_is_success", err_is_ok(err));
    TEST("single_is_one", p.num_parts == 1);
    TEST("single_is_correct", strcmp("name", p.parts[0]) == 0);

    free(p.parts);

    err = name_into_parts("top.bot", &p);

    TEST_ERR("double_is_success", err_is_ok(err));
    TEST("double_is_two", p.num_parts == 2);
    TEST("double_first_is_top", strcmp("top", p.parts[0]) == 0);
    TEST("double_second_is_bot", strcmp("bot", p.parts[1]) == 0);

    free(p.parts);
    END_TESTS;
}

static void run_insert_find_test(void) {
    BEGIN_TESTS("insert_find");

    errval_t err;

    err = initialize_name_tree();   
    TEST_ERR("init tree", err_is_ok(err));
    
    service_info_t *info1;
    service_info_new(0, NULL, NULL, 3, "name1", &info1);
    err = insert_name("name1", info1);
    TEST_ERR("insert name1", err_is_ok(err));

    print_service_names();

    service_info_t *ret1;
    err = find_name("name1", &ret1);
    TEST_ERR("find name1", err_is_ok(err));

    service_info_t *info2;
    service_info_new(0, NULL, NULL, 4, "test.name2", &info2);
    err = insert_name("test.name2", info2);
    TEST_ERR("insert test.name2", err_is_ok(err));

    print_service_names();

    service_info_t *ret2;
    err = find_name("test.name2", &ret2);
    TEST_ERR("find test.name2", err_is_ok(err));

    service_info_t *info3;
    service_info_new(0, NULL, NULL, 5, "test.name3", &info3);
    err = insert_name("test.name3", info3);
    TEST_ERR("insert test.name3", err_is_ok(err));

    print_service_names();

    service_info_t *ret3;
    err = find_name("test.name3", &ret3);
    TEST_ERR("find test.name3", err_is_ok(err));
    
    err = insert_name("name1", info1);
    TEST_ERR("fail inserting name1 again", err_no(err) == LIB_ERR_NAMESERVICE_NODE_EXISTS);



    END_TESTS;
}

__attribute__((unused))
static void run_nameservicetest(void) {
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t *pid = malloc(sizeof(domainid_t));
    errval_t err = spawn_process("nameservicetest", si, pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to spawn nameservicetest\n");
    }
    assert(err_is_ok(err));
}

void run_nameserver_tests(void)
{
    run_name_tests();
    run_name_part_tests();
    run_insert_find_test();
    //run_nameservicetest();
}