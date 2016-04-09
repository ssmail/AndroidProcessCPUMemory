__author__ = 'Chris Hong '


# introduce of this tool
# getProcessMemory.py is a tool that can get the Android devices specific
# process cpu and memory usage. it can recode the cpu and memory usage
# as a log file.
#
# you need to config the config.py to config the process which you need to
# monitor.
#
# the log file will generator as the same directory
# ProcessMonitor.log

import os
import re
import time
import subprocess

# the break time of each loop
BREAK_TIME = 10


ADB_DUMP_WINDOW_SHELL = "adb shell dumpsys meminfo"
ADB_DUMP_CPU_USAGE_SHELL = "adb shell top -n 1"

RE_FREE_MEMORY = "Free RAM:(\s\d+)"
RE_USAGE_MEMORY = "Used RAM:(\s\d+)"

RE_USER_CPU_USAGE = "User (\d+)%"
RE_SYS_CPU_USAGE = "System (\d+)%"


def exec_get_shell_output(shell_line):
    '''
    function description:   execute the shell line and get the output

    :param shell_line:
    :return the shell execution output:
    '''
    try:
        m_process = subprocess.Popen(shell_line, shell=True, stdout=subprocess.PIPE)
        std_out = m_process.stdout.read()
        if std_out:
            return std_out
        else:
            return False
    except Exception, e:
        print 'can not execute the shell --->  error reason : ', e
        return False


def get_sys_memory_info():
    '''
    get connected android devices system memory usage
    :return a tuple, 0 is system usage memory, 1 index is system free memory:
    '''
    usage_mem = ""
    free_mem = ""

    std_out = exec_get_shell_output(ADB_DUMP_WINDOW_SHELL)

    if std_out:
        free_mem = re.findall(RE_FREE_MEMORY, std_out)
        usage_mem = re.findall(RE_USAGE_MEMORY, std_out)

    if free_mem:
        return int(usage_mem[0]), int(free_mem[0])
    else:
        return None, None


def get_sys_cpu_usage():
    '''
    function description:   get system total cpu usage

    :return a tuple, 0 index is user cpu usage, 1 index is system cpu usage:
    '''
    user_cpu_usage = ""
    system_cpu_usage = ""

    std_out = exec_get_shell_output(ADB_DUMP_CPU_USAGE_SHELL)

    if std_out:
        user_cpu_usage = re.findall(RE_USER_CPU_USAGE, std_out)
        system_cpu_usage = re.findall(RE_SYS_CPU_USAGE, std_out)

    if user_cpu_usage:
        return int(user_cpu_usage[0]), int(system_cpu_usage[0])
    else:
        return None, None

def get_specific_process_mem_cpu(process_name):
    '''
    function description: get process memory and cpu usage
    return a tuple, 1st is cpu usage
    2nd is the memory usage, index 0 is virtual memory is virtual memory usage
                             index 1 is the real memory usage
    :param process_name:
    :return:
    '''
    RE_PROCESS_INFO = r".+" + process_name + r'\s'
    RE_PROCESS_INFO_MEM = "(\d+)K\s+(\d+)K.*" + process_name
    RE_PROCESS_INFO_CPU = "(\d+)%.*" + process_name

    process_info = ""

    std_out = exec_get_shell_output(ADB_DUMP_CPU_USAGE_SHELL)

    if std_out:
        process_info = re.findall(RE_PROCESS_INFO, std_out)

        if len(process_info) == 1:
            process_cpu_usage = re.findall(RE_PROCESS_INFO_CPU, process_info[0])
            process_mem_usage = re.findall(RE_PROCESS_INFO_MEM, process_info[0])
            return process_cpu_usage[0], process_mem_usage[0]
        elif len(process_info) > 1:
            print 'more than 1 process named :{process_name}'.format(process_name = process_name)
            exit(-1)
        elif len(process_info) < 1:
            print 'no process named: {process_name}'.format(process_name = process_name)
            exit(-2)


def get_time():
    return time.strftime(u'%Y-%m-%d  %H:%M:%S', time.localtime(time.time())) + "    "

def write_log_title(fp_log, title):
    with open(fp_log, 'a') as f:
        f.writelines(title + "\n")

def write_log_content(fp_log, c):
    with open(fp_log, 'a') as f:
        f.writelines(c + "\n")


def monitor_process(process_name):
    '''
        this function will record the specific process
        cpu and memory usage as a log file named test.log.

        you can config the interval time in the global various
        BREAK_TIME

    '''
    # start to write log file, write log title
    fp_log_path = os.path.join(os.getcwd(), "test.log")

    if os.path.exists(fp_log_path):
        os.remove(fp_log_path)

    write_log_title(fp_log_path, "{TIME}{PROCESS:30}{CPU:10}{MEMORY:10}{SYS_CPU:10}  "
                                 "{SYS_MEMORY_USAGE:20}{SYS_MEMORY_FREE:20}".format(
                                                                                    TIME = "Time" + 20 * " ",
                                                                                    PROCESS = "Process",
                                                                                    CPU = "CPU",
                                                                                    MEMORY= "Memory",
                                                                                    SYS_CPU = "system cpu",
                                                                                    SYS_MEMORY_USAGE ="System memory",
                                                                                    SYS_MEMORY_FREE = "System free memory"))
    #  get_sys_memory_info
    #  get_total_cpu_usage
    # get_specific_process_mem_cpu
    #

    # entry a loop to monitor the specific process
    try:
        while 1:

            sys_memory = get_sys_memory_info()
            sys_cpu = get_sys_cpu_usage()
            process_info = get_specific_process_mem_cpu(process_name)

            # print '---' * 10
            # print 'process info: ', process_info
            # print 'sys memory :', sys_memory
            # print 'sys cpu:', sys_cpu
            # print '---' * 10
            #
            #
            # print 'cpu ', process_info[0]
            # print 'memory', process_info[1][1]
            #
            # print 'sys_cpu', sys_cpu[0] + sys_cpu[1]
            # print 'sys_memory', sys_memory[0]

            write_log_content(fp_log_path, get_time() + "{process:30} {cpu:8} {memory:10} "
                                                        "{sys_cpu:10} {sys_memory:20} {sys_memory_free:20}".format(
                process = process_name, cpu = str(process_info[0]) + "%", memory = str(process_info[1][1]) + "kb",
                sys_cpu = str(sys_cpu[1]) + "%",
                sys_memory = str(sys_memory[0]) + "kb",
                sys_memory_free = str(sys_memory[1]) + "kb"
            ))

            time.sleep(BREAK_TIME)

    except KeyboardInterrupt, e:
        print 'user interrupt process by keyboard'
    except Exception, e:
        print 'unknown exception :', e


if "__main__" == __name__:
    monitor_process("com.geili.koudai")

# write_log_content(fp_log_path, get_time() + "test1")
#  write_log_content(fp_log_path, get_time() + "test2")

# exec_get_shell_output_test2()
# print exec_get_shell_output_test1("adb shell top -n 1")
#get_specific_process_mem_cpu("/sbin/watchdogd")
