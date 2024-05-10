#include <string.h>
#define ADDR_SIZE 16
#define MAX_PROCESSES 10 // 최대 프로세스 수
#define PAGE_SIZE 64
#define PFNUM 5     // 물리 메모리 프레임 수
#define SFNUM 16384 // 스왑 공간 프레임 수
#define MAX_FRAMES 4096

struct pcb
{
    unsigned short pid;
    FILE *fd;
    unsigned short *pgdir;
    int is_in_memory;     // 프로세스가 현재 메모리에 있는지 여부 (0: false, 1: true)
    unsigned int vbase;   // 가상 메모리 시작 주소
    unsigned int vlength; // 가상 메모리 사용 길이
                          /* Add more fields as needed */
};
int page_directory_frames[10];
struct pcb *current;
unsigned short *pdbr; // 페이지 디렉토리 베이스 레지스터
char *pmem, *swaps;   // 물리 메모리, 스왑 공간

void ku_dump_pmem(void);
void ku_dump_swap(void);
void enqueue(int frame_number);

int pfnum;                 // 페이지 프레임
int sfnum;                 // 스왑 프레임 수
int pmem_free_list[PFNUM]; // 전역 배열로 선언
int swap_free_list[SFNUM]; // 스왑 공간 자유 목록

struct pcb pcb[MAX_PROCESSES]; // 전역 PCB 배열 선언

int fifo_queue[MAX_FRAMES];  // FIFO 큐
int front = 0;               // 큐의 시작
int rear = 0;                // 큐의 끝
int frame_usage[MAX_FRAMES]; // 프레임 사용 상태

int is_page_directory_frame(int frame_number)
{
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (page_directory_frames[i] == frame_number)
        {
            return 1; // 페이지 디렉토리 프레임임
        }
    }
    return 0; // 일반 프레임임
}

int find_free_frame()
{
    for (int i = 0; i < PFNUM; i++)
    {
        if (pmem_free_list[i] == 0)
        {                          // 0은 사용 가능한 상태를 나타냅니다.
            pmem_free_list[i] = 1; // 프레임을 사용 중으로 표시
            enqueue(i);            // 프레임 번호를 FIFO 큐에 추가
            return i;              // 사용 가능한 프레임의 인덱스 반환
        }
    }
    return -1; // 사용 가능한 프레임이 없음
}

int find_swap_frame()
{
    for (int i = 0; i < SFNUM; i++)
    {
        if (swap_free_list[i] == 0)
        {                          // 0은 사용 가능한 상태를 나타냅니다.
            swap_free_list[i] = 1; // 프레임을 사용 중으로 표시
            return i;              // 사용 가능한 프레임의 인덱스 반환
        }
    }
    return -1; // 사용 가능한 프레임이 없음
}

// 프레임을 FIFO 큐에 추가
void enqueue(int frame_number)
{
    if ((rear + 1) % MAX_FRAMES == front)
    {
        printf("Error: Queue is full\n");
        return;
    }
    fifo_queue[rear] = frame_number;
    rear = (rear + 1) % MAX_FRAMES;
}

// FIFO 큐에서 프레임 제거
int dequeue()
{
    if (front == rear)
    {
        printf("Error: Queue is empty\n");
        return -1;
    }
    int frame_number = fifo_queue[front];
    front = (front + 1) % MAX_FRAMES;
    return frame_number;
}

int evict_frame()
{
    if (front == rear)
    { // FIFO 큐가 비어 있는지 확인
        printf("Error: No frame available to evict\n");
        return -1;
    }

    int frame_to_evict = dequeue(); // FIFO 큐에서 가장 오래된 프레임을 꺼냄

    while (frame_to_evict != -1 && is_page_directory_frame(frame_to_evict))
    {
        enqueue(frame_to_evict);    // 페이지 디렉토리 프레임을 큐에 다시 넣음
        frame_to_evict = dequeue(); // 다음 프레임 시도
    }

    if (frame_to_evict == -1)
    {
        return -1; // 큐에서 프레임을 제대로 꺼내지 못했을 경우
    }

    int free_swap_frame = find_swap_frame();

    for (int pd_index = 0; pd_index < 32; pd_index++)
    {
        if (pdbr[pd_index] & 0x0001)
        { // 유효한 PDE 체크
            unsigned short *pt = (unsigned short *)(pmem + (pdbr[pd_index] >> 4) * PAGE_SIZE);
            for (int pt_index = 0; pt_index < 32; pt_index++)
            {
                if ((pt[pt_index] >> 4) == frame_to_evict)
                {
                    pt[pt_index] = (free_swap_frame << 2) | 0x0001; // 스왑 아웃된 프레임 정보 업데이트
                }
            }
        }
    }

    // 스왑 공간에 데이터 복사 (스왑 아웃)
    char *swap_space_address = swaps + free_swap_frame * PAGE_SIZE;
    char *frame_address = pmem + frame_to_evict * PAGE_SIZE;
    memcpy(swap_space_address, frame_address, PAGE_SIZE);

    // 프레임 초기화
    memset(frame_address, 0, PAGE_SIZE);

    return frame_to_evict; // 스왑 아웃되고 초기화된 프레임 반환
}

void ku_freelist_init()
{
    // 페이지 디렉토리 넘버 저장하는 배열 초기화
    for (int i = 0; i < 10; i++)
    {
        page_directory_frames[i] = -1;
    }

    // 물리 메모리 자유  초기화
    for (int i = 0; i < pfnum; i++)
    {
        pmem_free_list[i] = 0; // 0: 사용 가능, 1: 사용 중
    }

    // 스왑 공간 자유 목록 초기화
    for (int i = 0; i < sfnum; i++)
    {
        swap_free_list[i] = 0;
    }
}

int ku_proc_init(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return -1;
    }

    FILE *input_file = fopen(argv[1], "r");
    if (!input_file)
    {
        perror("Failed to open input file");
        return -1;
    }

    int pid;
    char proc_filename[256];
    while (fscanf(input_file, "%d %s", &pid, proc_filename) == 2)
    {
        if (pid >= MAX_PROCESSES)
        {
            fprintf(stderr, "Process ID %d exceeds maximum allowed processes.\n", pid);
            continue; // 이 ID를 무시하고 계속 진행
        }

        pcb[pid].pid = pid;
        pcb[pid].fd = fopen(proc_filename, "r");
        if (pcb[pid].fd == NULL)
        {
            perror("Failed to open process file");
            continue; // 파일 열기 실패 시 무시
        }

        // 페이지 디렉토리에 물리 프레임 할당
        int frame_number = find_free_frame();
        if (frame_number == -1)
        {
            frame_number = evict_frame(); // 필요 시 스왑 아웃하여 프레임 확보
            if (frame_number == -1)
            {
                fprintf(stderr, "No free frame available even after eviction.\n");
                return -1; // 스왑 아웃도 실패한 경우 에러 반환
            }
        }

        // pafe_directory_frames 배열 관리
        page_directory_frames[pid] = frame_number;

        pcb[pid].pgdir = (unsigned short *)(pmem + frame_number * PAGE_SIZE); // 페이지 디렉토리 프레임 설정
        memset(pcb[pid].pgdir, 0, PAGE_SIZE);                                 // 페이지 디렉토리 초기화

        // 파일의 첫 두 줄에서 vbase와 vlength 읽기
        char segment_type;
        unsigned int start, length;
        if (fscanf(pcb[pid].fd, "%c\n%u %u", &segment_type, &start, &length) == 3)
        {
            pcb[pid].vbase = start;
            pcb[pid].vlength = length;
        }
        else
        {
            fprintf(stderr, "Error reading virtual memory info for PID %d\n", pid);
            fclose(pcb[pid].fd);
            pcb[pid].fd = NULL;
            continue; // 데이터 읽기 실패 시 파일 닫고 계속 진행
        }

        pcb[pid].is_in_memory = 1; // 프로세스 메모리 상태 설정
    }

    fclose(input_file);
    return 0;
}

int ku_scheduler(unsigned short arg1)
{
    unsigned short current_pid;
    unsigned short next_pid;

    // 첫 호출 처리
    if (arg1 == 10)
    {
        current_pid = MAX_PROCESSES - 1; // 최대 프로세스 수에서 1을 뺀 값으로 초기화
    }
    else
    {
        current_pid = arg1; // 일반 호출에서는 전달받은 PID 사용
    }

    next_pid = (current_pid + 1) % MAX_PROCESSES; // 다음 PID 계산

    // 메모리에 존재하는 프로세스를 찾기
    do
    {
        if (pcb[next_pid].is_in_memory)
        {
            current = &pcb[next_pid]; // 메모리에 있는 다음 프로세스를 현재 프로세스로 설정
            pdbr = current->pgdir;    // 현재 프로세스의 페이지 디렉토리로 pdbr 갱신
            return 0;                 // 성공적으로 스케줄링 완료
        }
        next_pid = (next_pid + 1) % MAX_PROCESSES; // 다음 PID 계산
    } while (next_pid != current_pid);

    // 모든 프로세스가 메모리에 없는 경우
    return 1; // 에러 코드 반환                // 성공적으로 스케줄링 완료
}

int ku_pgfault_handler(unsigned short arg1)
{
    // segmentation fault 를 발생시켜야함 (아직 구현 안함)
    unsigned int vbase = current->vbase;
    unsigned int vlength = current->vlength;

    // 전달된 가상 주소가 유효한 범위 내에 있는지 확인
    if (arg1 < vbase || arg1 >= vbase + vlength)
    {
        // 가상 주소가 프로세스의 메모리 범위를 벗어났을 경우, segmentation fault 처리
        return 1; // segmentation fault 오류 코드 반환
    }

    unsigned short pd_index = (arg1 >> 10) & 0x1F; // 페이지 디렉토리 인덱스 추출
    unsigned short pt_index = (arg1 >> 6) & 0x3F;  // 페이지 테이블 인덱스 추출

    unsigned short *pd_entry = &pdbr[pd_index]; // 페이지 디렉토리 엔트리 접근

    // 페이지 디렉토리 엔트리 검증
    if (!(*pd_entry & 0x0001))
    {
        if (*pd_entry == 0x0000)
        {
            int frame_number = find_free_frame(); // 물리 프레임 탐색
            if (frame_number == -1)
            {
                frame_number = evict_frame(); // FIFO 방식으로 프레임 하나를 스왑 아웃
                if (frame_number == -1)
                {
                    return 1; // 스왑공간에도 빈 공간이 없음
                }
            }
            memset(pmem + frame_number * PAGE_SIZE, 0, PAGE_SIZE); // 페이지 테이블 초기화
            *pd_entry = (frame_number << 4) | 0x0001;
        }
        else if (!(*pd_entry & 0x0001) && (*pd_entry & 0xFFFE))
        {
            // Swapped out 되어 있음
            int swap_frame_number = *pd_entry >> 2;   // 스왑 프레임 번호 추출
            int new_frame_number = find_free_frame(); // 새 프레임 할당
            if (new_frame_number == -1)
            {
                if (new_frame_number == -1)
                {
                    new_frame_number = evict_frame(); // FIFO 방식으로 프레임 하나를 스왑 아웃
                    if (new_frame_number == -1)
                    {
                        return 1; // 스왑공간에도 빈 공간이 없음
                    }
                }
            }
            // 스왑 공간의 주소 계산: 스왑 공간 시작 주소 + (스왑 프레임 번호 * 페이지 크기)
            char *swap_space_address = swaps + (swap_frame_number * PAGE_SIZE);
            // 물리 메모리의 새 프레임 주소 계산: 물리 메모리 시작 주소 + (물리 프레임 번호 * 페이지 크기)
            char *physical_memory_address = pmem + (new_frame_number * PAGE_SIZE);
            // 스왑 공간에서 물리 메모리로 데이터 복사
            memcpy(physical_memory_address, swap_space_address, PAGE_SIZE);
            memset(swap_space_address, 0, PAGE_SIZE); // 필요한 경우 스왑 공간의 데이터를 0으로 초기화
        }
    }

    unsigned short *pt = (unsigned short *)(pmem + (*pd_entry >> 4) * PAGE_SIZE); // 페이지 테이블 접근
    unsigned short *pt_entry = &pt[pt_index];                                     // 페이지 테이블 엔트리 접근

    if (!(*pt_entry & 0x0001)) // present bit이 0인 경우
    {
        // 1. 맵핑이 아예 안되어 있는 경우 즉 0000 0000 0000 0000 인 경우
        // 2. swapped out 되어 있는 경우
        if (*pt_entry == 0x0000)
        {
            // 맵핑이 아예 되어 있지 않음
            int frame_number = find_free_frame(); // 프리 프레임 탐색
            if (frame_number == -1)
            {
                frame_number = evict_frame(); // FIFO 방식으로 프레임 하나를 스왑 아웃
                if (frame_number == -1)
                {
                    return 1; // 스왑공간에도 빈 공간이 없음
                }
            }
            *pt_entry = (frame_number << 4) | 0x0001;
        }
        else if (!(*pt_entry & 0x0001) && (*pt_entry & 0xFFFE))
        {
            // Swapped out 되어 있음
            int swap_frame_number = *pt_entry >> 2;   // 스왑 프레임 번호 추출
            int new_frame_number = find_free_frame(); // 새 프레임 할당
            if (new_frame_number == -1)
            {
                if (new_frame_number == -1)
                {
                    new_frame_number = evict_frame(); // FIFO 방식으로 프레임 하나를 스왑 아웃
                    if (new_frame_number == -1)
                    {
                        return 1; // 스왑공간에도 빈 공간이 없음
                    }
                }
            }
            // 스왑 공간의 주소 계산: 스왑 공간 시작 주소 + (스왑 프레임 번호 * 페이지 크기)
            char *swap_space_address = swaps + (swap_frame_number * PAGE_SIZE);
            // 물리 메모리의 새 프레임 주소 계산: 물리 메모리 시작 주소 + (물리 프레임 번호 * 페이지 크기)
            char *physical_memory_address = pmem + (new_frame_number * PAGE_SIZE);
            // 스왑 공간에서 물리 메모리로 데이터 복사
            memcpy(physical_memory_address, swap_space_address, PAGE_SIZE);
            memset(swap_space_address, 0, PAGE_SIZE); // 필요한 경우 스왑 공간의 데이터를 0으로 초기화
        }
    }

    // present bit 이 1인경우 즉 이경우 걍 검색하면 됨
    // if ((*pt_entry & 0x0001))

    return 0; // 성공적으로 페이지 폴트 처리 완료
}

int ku_proc_exit(unsigned short arg1)
{
    // arg1을 pid로 사용합니다.
    unsigned short pid = arg1;

    int found = -1;
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
        if (pcb[i].pid == pid)
        {
            found = i;
            break;
        }
    }

    if (found == -1)
    {
        return 1; // PID가 유효하지 않거나 프로세스가 존재하지 않는 경우
    }

    if (pcb[found].is_in_memory == 0)
    {
        return 1; // 해제 하려는 프로세스가 메모리에 있지 않은 경우
    }

    // 페이지 디렉토리 프레임 번호를 -1로 설정하여 회수 표시
    int pd_frame_number = page_directory_frames[pid];
    if (pd_frame_number != -1)
    {
        pmem_free_list[pd_frame_number] = 0; // 해당 프레임을 사용 가능으로 표시
        page_directory_frames[pid] = -1;     // 배열에서 해당 프레임 번호를 -1로 업데이트
    }

    // 프로세스의 페이지 디렉토리에 대한 메모리 해제 및 페이지 프레임 회수
    for (int i = 0; i < 32; i++) // PDE 는 32개
    {
        unsigned short pde = pcb[found].pgdir[i];
        if (pde & 0x0001)
        { // PDE가 'present'일 경우, 페이지 테이블 처리
            unsigned short *pt = (unsigned short *)(pmem + (pde >> 4) * PAGE_SIZE);
            for (int j = 0; j < 32; j++) // PTE도 32개
            {
                if (pt[j] & 0x0001)
                { // PTE가 'present'일 경우, 해당 프레임을 free list에 추가
                    int frame_number = pt[j] >> 4;
                    pmem_free_list[frame_number] = 0;
                }
                else if (pt[j] != 0)
                { // 스왑 아웃된 상태라면
                    int swap_frame_number = pt[j] >> 2;
                    swap_free_list[swap_frame_number] = 0;
                }
            }
            pmem_free_list[pde >> 4] = 0;
        }
        else if (pde != 0) // PDE가 스왑 아웃된 경우
        {
            int swap_frame_number = pde >> 2;
            swap_free_list[swap_frame_number] = 0;
        }
    }

    free(pcb[found].pgdir);
    pcb[found].pgdir = NULL;

    // 파일 디스크립터 닫기
    if (pcb[found].fd != NULL)
    {
        fclose(pcb[found].fd);
        pcb[found].fd = NULL;
    }

    // PCB 초기화
    pcb[found].is_in_memory = 0;
    pcb[found].pid = 0;

    return 0; // 성공적으로 종료 처리 완료
}