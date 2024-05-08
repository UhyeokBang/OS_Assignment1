#define ADDR_SIZE 16
#define MAX_PROCESSES 10 // 최대 프로세스 수
#define NUM_PAGES 1024   // 총 페이지 수
#define PAGE_SIZE 64
#define PFNUM 4096  // 물리 메모리 프레임 수
#define SFNUM 16384 // 스왑 공간 프레임 수

struct pcb
{
    unsigned short pid;
    FILE *fd;
    unsigned short *pgdir;
    int is_in_memory;           // 프로세스가 현재 메모리에 있는지 여부 (0: false, 1: true)
    unsigned short *page_table; // 페이지 테이블 추가
                                /* Add more fields as needed */
};

struct pcb *current;
unsigned short *pdbr; // 페이지 디렉토리 베이스 레지스터
char *pmem, *swaps;   // 물리 메모리, 스왑 공간

void ku_dump_pmem(void);
void ku_dump_swap(void);

int pfnum;                 // 페이지 프레임 수
int sfnum;                 // 스왑 프레임 수
int pmem_free_list[PFNUM]; // 전역 배열로 선언
int swap_free_list[SFNUM]; // 스왑 공간 자유 목록

struct pcb pcb[MAX_PROCESSES]; // 전역 PCB 배열 선언

int find_free_frame()
{
    for (int i = 0; i < pfnum; i++)
    {
        if (pmem_free_list[i] == 0)
        {                          // 0은 사용 가능한 상태를 나타냅니다.
            pmem_free_list[i] = 1; // 프레임을 사용 중으로 표시
            return i;              // 사용 가능한 프레임의 인덱스 반환
        }
    }
    return -1; // 사용 가능한 프레임이 없음
}

void ku_freelist_init()
{
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
        pcb[pid].pgdir = calloc(NUM_PAGES, sizeof(unsigned short));
        pcb[pid].page_table = calloc(NUM_PAGES, sizeof(unsigned short));
        pcb[pid].is_in_memory = 0; // 초기 메모리 상태는 아님
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
    unsigned short pd_index = (arg1 >> 10) & 0x1F; // 페이지 디렉토리 인덱스 추출
    unsigned short pt_index = (arg1 >> 6) & 0x3F;  // 페이지 테이블 인덱스 추출

    unsigned short *pd_entry = &pdbr[pd_index]; // 페이지 디렉토리 엔트리 접근

    // 페이지 디렉토리 엔트리 검증
    if (!(*pd_entry & 0x0001))
    {                                         // PDE가 유효하지 않은 경우, 새 PT 할당
        int frame_number = find_free_frame(); // 물리 프레임 탐색
        if (frame_number == -1)
        {
            return 1; // 사용 가능한 프레임 없음, 오류 반환
        }
        *pd_entry = (frame_number << 6) | 0x0001;              // 새 프레임 할당 및 PDE 설정
        memset(pmem + frame_number * PAGE_SIZE, 0, PAGE_SIZE); // 페이지 테이블 초기화
    }

    unsigned short *pt = (unsigned short *)(pmem + (*pd_entry >> 6) * PAGE_SIZE); // 페이지 테이블 접근
    unsigned short *pt_entry = &pt[pt_index];                                     // 페이지 테이블 엔트리 접근

    if (!(*pt_entry & 0x0001))
    {                                         // PTE가 유효하지 않은 경우
        int frame_number = find_free_frame(); // 프리 프레임 탐색
        if (frame_number == -1)
        {
            return 1; // 사용 가능한 프레임 없음, 오류 반환
        }
        *pt_entry = (frame_number << 6) | 0x0001;              // PTE 설정
        memset(pmem + frame_number * PAGE_SIZE, 0, PAGE_SIZE); // 신규 프레임 초기화
    }

    // 스왑된 페이지가 있는 경우, 스왑 인 처리
    if (*pt_entry & 0x0002)
    {
        perform_swap_in(*pt_entry >> 6); // 스왑 인 로직
    }

    // PTE 업데이트 (dirty 및 present 비트 설정)
    *pt_entry |= 0x0003;

    update_free_lists(); // 프리 리스트 업데이트

    return 0; // 성공적으로 페이지 폴트 처리 완료
}

int ku_proc_exit(unsigned short arg1)
{
    // arg1을 pid로 사용합니다.
    unsigned short pid = arg1;

    // pcb 배열에서 해당 pid의 프로세스 정보를 확인하고, 자원을 해제합니다.
    if (pcb[pid].fd != NULL)
    {
        fclose(pcb[pid].fd);       // 파일 핸들을 닫습니다.
        free(pcb[pid].pgdir);      // 할당된 페이지 디렉토리 메모리를 해제합니다.
        free(pcb[pid].page_table); // 할당된 페이지 테이블 메모리를 해제합니다.
        pcb[pid].fd = NULL;        // 파일 디스크립터를 NULL로 설정합니다.
        pcb[pid].is_in_memory = 0; // 메모리에 있음 상태를 0으로 설정합니다.
    }

    return 0; // 성공적으로 종료 처리를 완료했습니다.
}