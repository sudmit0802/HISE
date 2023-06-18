#ifndef HISE_SIGN_API_HPP
#define HISE_SIGN_API_HPP

#include "../global_escrow_hise/global_escrow_hise1.hpp"
#include <vector>
#include <chrono>

std::tuple<Global_Escrow_HISE_PP, G2, Fr> setup(void)
{
    srand(time(NULL));

    Global_Escrow_HISE_PP pp; // it's like a context for everything

    Fr s;
    G2 esk; // super key for boss (he can use this key for decrypting any message)
    Global_Escrow_HISE_Setup(pp, esk, s);

    return std::make_tuple(pp, esk, s);
}

std::tuple<G1, G2, Fr> keygen(Global_Escrow_HISE_PP &pp)
{

    Fr sk; // random secret for generating dk
    G1 pk; // public key
    Global_Escrow_HISE_KeyGen(pp, pk, sk);

    G2 dk; // private key
    Global_Escrow_HISE_Derive(pp, sk, dk);

    return std::make_tuple(pk, dk, sk);
}

Global_Escrow_HISE_CT encrypt(Global_Escrow_HISE_PP &pp, G1 &pk, std::string &message)
{
    // plain text
    GT pt;

    std::string msg = message.substr(0, 32);
    std::string arg_str = "0b" + asciiToBinary(msg);
    arg_str += " 0 0 0 0 0 0 0 0 0 0 0";
    pt.setStr(arg_str, 2);

    Global_Escrow_HISE_CT ct; // placeholder for cipher-text
    Global_Escrow_HISE_Encrypt(pp, pk, pt, ct);

    return ct;
}

std::string decrypt(Global_Escrow_HISE_PP &pp, G2 &dk, Global_Escrow_HISE_CT &ct)
{
    GT pt_prime; // decrypted text
    Global_Escrow_HISE_Decrypt(pp, dk, ct, pt_prime);
    std::string decrypted = pt_prime.getStr(2);

    std::vector<std::string> substrings = split(decrypted, ' ');
    std::string tmp_str = substrings.front();
    int number_of_lead_zeroes = 256 - tmp_str.length();
    std::string zeroes(number_of_lead_zeroes, '0');
    tmp_str = zeroes + tmp_str;
    std::string ret_str = binaryToAscii(tmp_str);
    return ret_str;
}

std::string super_decrypt(Global_Escrow_HISE_PP &pp, G2 &esk, Global_Escrow_HISE_CT &ct)
{

    GT pt_prime; // decrypted text
    Global_Escrow_HISE_Escrow_Decrypt(pp, esk, ct, pt_prime);
    std::string decrypted = pt_prime.getStr(2);

    std::vector<std::string> substrings = split(decrypted, ' ');
    std::string tmp_str = substrings.front();
    int number_of_lead_zeroes = 256 - tmp_str.length();
    std::string zeroes(number_of_lead_zeroes, '0');
    tmp_str = zeroes + tmp_str;
    std::string ret_str = binaryToAscii(tmp_str);
    return ret_str;
}

G2 sign(Fr &sk, std::string &msg)
{
    G2 sig;
    Global_Escrow_HISE_Sign(sk, msg, sig);

    return sig;
}

bool verify(Global_Escrow_HISE_PP &pp, G1 &pk, std::string &msg, G2 &sig)
{
    return Global_Escrow_HISE_Verify(pp, pk, msg, sig);
}

#endif