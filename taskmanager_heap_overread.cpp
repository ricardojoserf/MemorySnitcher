#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <limits>
#include <iomanip>

using namespace std;

struct Task {
    int id;
    string description;
    string creationDate;
    string dueDate;
    int priority;
    bool completed;

    Task(int i, const string& desc, const string& due, int prio)
        : id(i), description(desc), priority(prio), completed(false) {
        time_t now = time(nullptr);
        char timeStr[26];
        ctime_s(timeStr, sizeof(timeStr), &now);
        creationDate = timeStr;
        dueDate = due.empty() ? "Not specified" : due;
    }
};

class TaskManager {
private:
    vector<Task> tasks;
    int nextId;

    void displayTask(const Task& t) const {
        cout << "ID: " << t.id << endl;
        cout << "Description: " << t.description << endl;
        cout << "Created: " << t.creationDate;
        cout << "Due: " << t.dueDate << endl;
        cout << "Priority: " << string(t.priority, '*') << endl;
        cout << "Status: " << (t.completed ? "Completed" : "Pending") << endl;
        cout << "----------------------------------" << endl;
    }

public:
    TaskManager() : nextId(1) {}

    void addTask() {
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        string description, dueDate;
        int priority;

        cout << "Enter task description: ";
        getline(cin, description);

        cout << "Enter due date (optional, DD/MM/YYYY format): ";
        getline(cin, dueDate);

        cout << "Enter priority (1-5): ";
        while (!(cin >> priority) || priority < 1 || priority > 5) {
            cout << "Invalid priority. Enter a number between 1 and 5: ";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }

        tasks.emplace_back(nextId++, description, dueDate, priority);
        cout << "Task added successfully!\n";
    }

    void listTasks() const {
        if (tasks.empty()) {
            cout << "No tasks to display.\n";
            return;
        }

        cout << "\n=== TASK LIST ===\n";
        for (const auto& task : tasks) {
            displayTask(task);
        }
    }

    void markCompleted() {
        if (tasks.empty()) {
            cout << "No tasks to mark as completed.\n";
            return;
        }

        listTasks();
        int id;
        cout << "Enter ID of completed task: ";
        while (!(cin >> id)) {
            cout << "Invalid ID. Enter a number: ";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }

        auto it = find_if(tasks.begin(), tasks.end(), [id](const Task& t) { return t.id == id; });
        if (it != tasks.end()) {
            it->completed = true;
            cout << "Task marked as completed.\n";
        }
        else {
            cout << "Task not found.\n";
        }
    }

    void removeTask() {
        if (tasks.empty()) {
            cout << "No tasks to remove.\n";
            return;
        }

        listTasks();
        int id;
        cout << "Enter ID of task to remove: ";
        while (!(cin >> id)) {
            cout << "Invalid ID. Enter a number: ";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }

        auto it = find_if(tasks.begin(), tasks.end(), [id](const Task& t) { return t.id == id; });
        if (it != tasks.end()) {
            tasks.erase(it);
            cout << "Task removed successfully.\n";
        }
        else {
            cout << "Task not found.\n";
        }
    }

    void saveToFile() const {
        ofstream file("tasks.txt");
        if (!file) {
            cout << "Error saving tasks to file.\n";
            return;
        }

        for (const auto& task : tasks) {
            file << task.id << "\n";
            file << task.description << "\n";
            file << task.creationDate;
            file << task.dueDate << "\n";
            file << task.priority << "\n";
            file << task.completed << "\n";
        }

        cout << "Tasks saved to file.\n";
    }

    void loadFromFile() {
        ifstream file("tasks.txt");
        if (!file) {
            cout << "No saved tasks found.\n";
            return;
        }

        tasks.clear();
        string line;
        while (getline(file, line)) {
            Task task(stoi(line), "", "", 1);
            getline(file, task.description);
            getline(file, task.creationDate);
            getline(file, task.dueDate);
            file >> task.priority;
            file >> task.completed;
            file.ignore();
            tasks.push_back(task);
            nextId = max(nextId, task.id + 1);
        }

        cout << "Tasks loaded from file.\n";
    }


    void test() {
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");
        FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");

        char *buffer = (char *)malloc(32);
        strcpy(buffer, "leak");
        uintptr_t *leakme1 = (uintptr_t *)(buffer + 16);
        *leakme1 = (uintptr_t)pNtReadVirtualMemory;
        
        for (int i = 23; i >= 16; i--) { printf("%02X", (unsigned char)buffer[i]); }
        
        return;
    }


    void showMenu() {
        int choice;
        do {
            cout << "\n=== TASK MANAGER ===\n";
            cout << "1. Add Task\n";
            cout << "2. List Tasks\n";
            cout << "3. Mark Task as Completed\n";
            cout << "4. Remove Task\n";
            cout << "5. Save Tasks to File\n";
            cout << "6. Load Tasks from File\n";
            cout << "0. Exit\n";
            cout << "Enter your choice: ";

            while (!(cin >> choice)) {
                cout << "Invalid input. Enter a number: ";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }

            switch (choice) {
            case 1: addTask(); break;
            case 2: listTasks(); break;
            case 3: markCompleted(); break;
            case 4: removeTask(); break;
            case 5: saveToFile(); break;
            case 6: loadFromFile(); break;
            case 33: test(); break;
            case 0: cout << "Exiting...\n"; break;
            default: cout << "Invalid choice. Try again.\n";
            }
        } while (choice != 0);
    }
};

int main() {
    TaskManager manager;
    manager.showMenu();
    return 0;
}