// #define LOG

#include "../api/hise_sign_api.hpp"

// Basic test. Boss can decrypt common communication member's messages
void test_1()
{
    std::cout << "Start test #1" << std::endl;

    auto setup_pair = setup();
    auto ctx = std::get<0>(setup_pair);
    auto super_key = std::get<1>(setup_pair);

    std::cout << std::endl;

    auto keys = keygen(ctx);
    auto public_key = std::get<0>(keys);
    auto private_key = std::get<1>(keys);

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    std::string msg_ref("TEST STRING FOR ENCRYPTION");

    std::string msg_1(msg_ref);
    auto cipher_text_1 = encrypt(ctx, public_key, msg_1);
    std::cout << "Encrypted by COMMON: " << cipher_text_1.Y2 << std::endl;
    auto decrypted_text_1 = decrypt(ctx, private_key, cipher_text_1);
    std::cout << "Decrypted by COMMON: " << decrypted_text_1 << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    std::string msg_2(msg_ref);
    auto cipher_text_2 = encrypt(ctx, public_key, msg_2);
    std::cout << "Encrypted by SUPER: " << cipher_text_2.Y2 << std::endl;
    auto decrypted_text_2 = super_decrypt(ctx, super_key, cipher_text_2);
    std::cout << "Decrypted by SUPER: " << decrypted_text_2 << std::endl;

    std::cout << "Finish test #1" << std::endl
              << std::endl;
    return;
}

// Boss can not forge a signature
void test_2()
{
    std::cout << "Start test #2" << std::endl;

    std::cout << "Finish test #2" << std::endl
              << std::endl;

    return;
}

// Boss can communicate with others as typical user using his super key (signing and encrypting)
void test_3()
{

    std::cout << "Start test #3" << std::endl;

    std::cout << "Finish test #3" << std::endl
              << std::endl;

    return;
}

// User addition to system, expand key set keeping boss key valid
void test_4()
{
    std::cout << "Start test #4" << std::endl;

    std::cout << "Finish test #4" << std::endl
              << std::endl;

    return;
}

// Check key compromise
void test_5()
{
    std::cout << "Start test #5" << std::endl;

    std::cout << "Finish test #5" << std::endl
              << std::endl;

    return;
}

int main(int argc, char **argv)
{
    test_1();
    test_2();
    test_3();
    test_4();
    test_5();

    return 0;
}
