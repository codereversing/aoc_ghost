#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Ws2_32.lib")

#include <Windows.h>
#include <stdio.h>
#include <include/detours.h>

#define PLAYER_INDEX 20
#define CHAT_FLAG_INDEX 21
#define CHAT_BROADCAST_INDEX 22
#define CHAT_MESSAGE_START_INDEX 37

#define CHAT_FLAG 0xDC

static int (WINAPI *psendto)(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) = sendto;
static int (WINAPI *precvfrom)(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) = recvfrom;

char *ghost_command = NULL;
char *new_packet_out = NULL;
char *ghost_key = "@ghost";
char *spy_key_on = "@spyon";
char *spy_key_off = "@spyoff";

unsigned char player_to_ghost = 0xFF;
bool is_spy_on = false;

int WINAPI recvfrom_hook(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    __asm pushad
    if ((buf[CHAT_FLAG_INDEX] & 0xFF) == CHAT_FLAG && is_spy_on == true) {
        memset((buf + CHAT_BROADCAST_INDEX), 0x59, 8);
    }
    int ret = precvfrom(s, buf, len, flags, from, fromlen);
    __asm popad
    return ret;
}

int WINAPI sendto_hook(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    __asm pushad
    memcpy(new_packet_out, buf, len);
    if ((new_packet_out[CHAT_FLAG_INDEX] & 0xFF) == CHAT_FLAG) {
        if ((ghost_command = strstr((new_packet_out + CHAT_MESSAGE_START_INDEX), ghost_key)) != NULL) {
            player_to_ghost = (ghost_command[strlen(ghost_key)] - 0x30) & 0xFF;
            memset((new_packet_out + CHAT_BROADCAST_INDEX), 0x4E, 8);
        }
        if (strstr((new_packet_out + CHAT_MESSAGE_START_INDEX), spy_key_on) != NULL) {
            is_spy_on = true;
            memset((new_packet_out + CHAT_BROADCAST_INDEX), 0x4E, 8);
        }
        else if (strstr((new_packet_out + CHAT_MESSAGE_START_INDEX), spy_key_off) != NULL) {
            is_spy_on = false;
            memset((new_packet_out + CHAT_BROADCAST_INDEX), 0x4E, 8);
        }
        if (player_to_ghost == 0x00 || player_to_ghost > 0x8)
            new_packet_out[PLAYER_INDEX] = 0xF;
        else
        {
            new_packet_out[PLAYER_INDEX] = player_to_ghost;
            new_packet_out[CHAT_BROADCAST_INDEX + (player_to_ghost - 1)] = 0x4E;
        }
    }
    int ret = psendto(s, new_packet_out, len, flags, to, tolen);
    __asm popad
    return ret;
}

int APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        new_packet_out = (char *)malloc(256 * sizeof(char));
        (void)DetourTransactionBegin();
        (void)DetourUpdateThread(GetCurrentThread());
        (void)DetourAttach(&(PVOID&)psendto, sendto_hook);
        (void)DetourAttach(&(PVOID&)precvfrom, recvfrom_hook);
        (void)DetourTransactionCommit();
    }
    return TRUE;
}