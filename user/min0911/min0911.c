#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

int main()
{
    struct tm event_tm =
        {
            .tm_year = 101,
            .tm_mon = 8,
            .tm_mday = 11,
            .tm_hour = 12,
            .tm_min = 46,
            .tm_sec = 0,
            .tm_isdst = -1,
        };

    time_t event_time = mktime(&event_tm);
    if (event_time < 0)
    {
        return -1;
    }

    time_t now_time;
    time(&now_time);

    struct tm *now_tm = gmtime(&now_time);

    time_t diff_secs = now_time - event_time;
    int64_t diff_mins = diff_secs / 60;

    // 输出结果
    printf("Time passed since September 11, 2001 12:46:00 UTC:\n");
    printf("%ld minutes\n", diff_mins);

    return 0;
}
