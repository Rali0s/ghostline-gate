#include "ghostline/operator_state.hpp"
#include "ghostline/pid_search.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTabWidget>
#include <QTextStream>
#include <QVBoxLayout>
#include <QWidget>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

QString to_qstring(const std::string& value) {
    return QString::fromStdString(value);
}

std::string to_std_string(const QString& value) {
    return value.toStdString();
}

std::string direction_text(Direction direction) {
    return direction == Direction::ClientToServer ? "client_to_server" : "server_to_client";
}

std::string process_summary(const ProcessSocketEntry& entry) {
    std::ostringstream out;
    out << "PID " << entry.pid << "  " << entry.command;
    if (!entry.user.empty()) {
        out << "  user=" << entry.user;
    }
    out << "  sockets=" << entry.sockets.size();
    return out.str();
}

std::string process_detail(const ProcessSocketEntry& entry) {
    std::ostringstream out;
    out << "PID: " << entry.pid << "\n"
        << "Command: " << entry.command << "\n"
        << "User: " << entry.user << "\n"
        << "Sockets:\n";
    for (const auto& socket : entry.sockets) {
        out << "  fd=" << socket.file_descriptor
            << " family=" << socket.address_family
            << " state=" << socket.state
            << " endpoint=" << socket.endpoint << "\n";
    }
    return out.str();
}

std::string review_summary(const ActionItem& item) {
    std::ostringstream out;
    out << item.action_id << "  [" << item.review_status << "]  "
        << item.plugin_name << "  flow=" << item.flow_id;
    return out.str();
}

std::string review_detail(const ActionItem& item) {
    std::ostringstream out;
    out << "Action: " << item.action_id << "\n"
        << "Status: " << item.review_status << "\n"
        << "Plugin: " << item.plugin_name << "\n"
        << "Flow: " << item.flow_id << "\n"
        << "Direction: " << direction_text(item.direction) << "\n"
        << "Title: " << item.title << "\n"
        << "Detail: " << item.detail << "\n"
        << "Trigger: " << item.trigger_id << "\n"
        << "Candidate: " << item.candidate_id << "\n"
        << "Validation: " << item.validation_label << "\n"
        << "Fallback: " << item.fallback_reason << "\n"
        << "Replay Count: " << item.replay_count << "\n"
        << "Decision Note: " << item.decision_note << "\n"
        << "Original Hex:\n" << item.original_hex << "\n\n"
        << "Modified Hex:\n" << item.modified_hex << "\n";
    return out.str();
}

std::string read_file_text(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open " + path);
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::vector<std::string> read_non_empty_lines(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open " + path);
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

std::string summarize_jsonl_line(const std::string& line) {
    auto extract = [&line](const std::string& key) {
        const std::string needle = "\"" + key + "\":";
        const std::size_t start = line.find(needle);
        if (start == std::string::npos) return std::string();
        const std::size_t quote = line.find('"', start + needle.size());
        if (quote == std::string::npos) return std::string();
        const std::size_t end = line.find('"', quote + 1);
        if (end == std::string::npos) return std::string();
        return line.substr(quote + 1, end - quote - 1);
    };

    const std::string action_id = extract("action_id");
    if (!action_id.empty()) {
        const std::string plugin = extract("plugin");
        const std::string status = extract("review_status");
        return action_id + " [" + status + "] " + plugin;
    }

    const std::string event_id = extract("event_id");
    const std::string stage = extract("stage");
    const std::string plugin = extract("plugin");
    if (!event_id.empty()) {
        return event_id + " [" + stage + "] " + plugin;
    }

    return line.size() > 96 ? line.substr(0, 96) + "..." : line;
}

class GhostlineOperatorWindow : public QWidget {
public:
    GhostlineOperatorWindow() {
        setWindowTitle("Ghostline Operator");
        resize(1220, 760);

        auto* root = new QVBoxLayout(this);

        auto* title = new QLabel("Ghostline Phase 1 Operator");
        QFont title_font = title->font();
        title_font.setPointSize(title_font.pointSize() + 6);
        title_font.setBold(true);
        title->setFont(title_font);

        auto* subtitle = new QLabel("Operate the finished CLI core through target discovery, saved profiles, and the pending review queue.");
        subtitle->setWordWrap(true);

        root->addWidget(title);
        root->addWidget(subtitle);

        auto* tabs = new QTabWidget;
        tabs->addTab(build_targets_tab(), "Targets");
        tabs->addTab(build_reviews_tab(), "Reviews");
        tabs->addTab(build_files_tab(), "Files");
        root->addWidget(tabs, 1);

        refresh_profiles();
        refresh_review_items();
    }

private:
    QWidget* build_targets_tab() {
        auto* tab = new QWidget;
        auto* layout = new QVBoxLayout(tab);
        auto* splitter = new QSplitter;

        auto* left = new QWidget;
        auto* left_layout = new QVBoxLayout(left);

        auto* search_group = new QGroupBox("PID Search");
        auto* search_form = new QFormLayout(search_group);

        process_input_ = new QLineEdit("ollama");
        pid_input_ = new QLineEdit;
        port_input_ = new QLineEdit;
        state_input_ = new QLineEdit;
        listen_only_input_ = new QCheckBox("Listen only");
        established_only_input_ = new QCheckBox("Established only");

        search_form->addRow("Process contains", process_input_);
        search_form->addRow("PID", pid_input_);
        search_form->addRow("Port", port_input_);
        search_form->addRow("State", state_input_);
        search_form->addRow("", listen_only_input_);
        search_form->addRow("", established_only_input_);

        auto* search_buttons = new QHBoxLayout;
        auto* search_button = new QPushButton("Search");
        auto* save_button = new QPushButton("Save Profile");
        auto* open_profile_file_button = new QPushButton("Open Profile File");
        search_buttons->addWidget(search_button);
        search_buttons->addWidget(save_button);
        search_buttons->addWidget(open_profile_file_button);
        search_form->addRow(search_buttons);

        search_results_ = new QListWidget;
        search_results_->setSelectionMode(QAbstractItemView::SingleSelection);
        search_form->addRow("Results", search_results_);

        left_layout->addWidget(search_group);

        auto* profile_group = new QGroupBox("Saved Profiles");
        auto* profile_layout = new QVBoxLayout(profile_group);

        auto* profile_dir_row = new QHBoxLayout;
        profiles_dir_input_ = new QLineEdit("ghostline_target_profiles");
        auto* refresh_profiles_button = new QPushButton("Refresh Profiles");
        auto* choose_profiles_dir_button = new QPushButton("Choose Dir");
        auto* seed_profiles_button = new QPushButton("Seed Protocol Profiles");
        profile_dir_row->addWidget(new QLabel("Directory"));
        profile_dir_row->addWidget(profiles_dir_input_, 1);
        profile_dir_row->addWidget(choose_profiles_dir_button);
        profile_dir_row->addWidget(seed_profiles_button);
        profile_dir_row->addWidget(refresh_profiles_button);

        auto* profile_save_row = new QHBoxLayout;
        profile_label_input_ = new QLineEdit("default-target");
        profile_file_input_ = new QLineEdit("target.json");
        profile_save_row->addWidget(new QLabel("Label"));
        profile_save_row->addWidget(profile_label_input_, 1);
        profile_save_row->addWidget(new QLabel("File"));
        profile_save_row->addWidget(profile_file_input_, 1);

        profiles_list_ = new QListWidget;
        auto* profile_actions = new QHBoxLayout;
        auto* load_profile_button = new QPushButton("Load Into Search");
        auto* show_profile_button = new QPushButton("Show Profile");
        profile_actions->addWidget(load_profile_button);
        profile_actions->addWidget(show_profile_button);

        profile_layout->addLayout(profile_dir_row);
        profile_layout->addLayout(profile_save_row);
        profile_layout->addWidget(profiles_list_, 1);
        profile_layout->addLayout(profile_actions);

        left_layout->addWidget(profile_group, 1);

        auto* right = new QWidget;
        auto* right_layout = new QVBoxLayout(right);
        auto* details_group = new QGroupBox("Target Details");
        auto* details_layout = new QVBoxLayout(details_group);
        target_details_ = new QPlainTextEdit;
        target_details_->setReadOnly(true);
        details_layout->addWidget(target_details_);
        right_layout->addWidget(details_group);

        splitter->addWidget(left);
        splitter->addWidget(right);
        splitter->setStretchFactor(0, 2);
        splitter->setStretchFactor(1, 3);
        layout->addWidget(splitter);

        connect(search_button, &QPushButton::clicked, this, [this]() { run_search(); });
        connect(save_button, &QPushButton::clicked, this, [this]() { save_profile_from_search(); });
        connect(open_profile_file_button, &QPushButton::clicked, this, [this]() { open_profile_file(); });
        connect(refresh_profiles_button, &QPushButton::clicked, this, [this]() { refresh_profiles(); });
        connect(choose_profiles_dir_button, &QPushButton::clicked, this, [this]() {
            const QString dir = QFileDialog::getExistingDirectory(this, "Choose target profile directory", profiles_dir_input_->text());
            if (!dir.isEmpty()) {
                profiles_dir_input_->setText(dir);
                refresh_profiles();
            }
        });
        connect(seed_profiles_button, &QPushButton::clicked, this, [this]() {
            try {
                const auto written = seed_protocol_target_profiles(to_std_string(profiles_dir_input_->text().trimmed()));
                refresh_profiles();
                QMessageBox::information(this,
                                         "Seed Protocol Profiles",
                                         "Seeded protocol profiles:\n" + to_qstring(std::to_string(written.size())) + " files written.");
            } catch (const std::exception& error) {
                QMessageBox::critical(this, "Seed Protocol Profiles", to_qstring(error.what()));
            }
        });
        connect(search_results_, &QListWidget::currentRowChanged, this, [this](int row) { show_search_result(row); });
        connect(profiles_list_, &QListWidget::currentRowChanged, this, [this](int row) { show_profile_result(row); });
        connect(load_profile_button, &QPushButton::clicked, this, [this]() { load_selected_profile_into_search(); });
        connect(show_profile_button, &QPushButton::clicked, this, [this]() { show_selected_profile_json(); });

        return tab;
    }

    QWidget* build_reviews_tab() {
        auto* tab = new QWidget;
        auto* layout = new QVBoxLayout(tab);
        auto* splitter = new QSplitter;

        auto* left = new QWidget;
        auto* left_layout = new QVBoxLayout(left);

        auto* queue_group = new QGroupBox("Pending Review Queue");
        auto* queue_layout = new QVBoxLayout(queue_group);

        auto* queue_dir_row = new QHBoxLayout;
        review_queue_dir_input_ = new QLineEdit("ghostline_review_queue");
        auto* choose_queue_button = new QPushButton("Choose Dir");
        auto* refresh_queue_button = new QPushButton("Refresh Queue");
        queue_dir_row->addWidget(new QLabel("Queue"));
        queue_dir_row->addWidget(review_queue_dir_input_, 1);
        queue_dir_row->addWidget(choose_queue_button);
        queue_dir_row->addWidget(refresh_queue_button);

        review_items_ = new QListWidget;
        queue_layout->addLayout(queue_dir_row);
        queue_layout->addWidget(review_items_, 1);

        auto* note_row = new QHBoxLayout;
        review_note_input_ = new QLineEdit;
        note_row->addWidget(new QLabel("Decision note"));
        note_row->addWidget(review_note_input_, 1);
        queue_layout->addLayout(note_row);

        auto* actions = new QHBoxLayout;
        auto* approve_button = new QPushButton("Approve");
        auto* reject_button = new QPushButton("Reject");
        auto* replay_button = new QPushButton("Replay");
        auto* open_review_file_button = new QPushButton("Open Review File");
        actions->addWidget(approve_button);
        actions->addWidget(reject_button);
        actions->addWidget(replay_button);
        actions->addWidget(open_review_file_button);
        queue_layout->addLayout(actions);

        left_layout->addWidget(queue_group);

        auto* replay_group = new QGroupBox("Replay Artifacts");
        auto* replay_layout = new QVBoxLayout(replay_group);
        auto* replay_dir_row = new QHBoxLayout;
        replay_dir_input_ = new QLineEdit("ghostline_replays");
        auto* choose_replay_button = new QPushButton("Choose Dir");
        replay_dir_row->addWidget(new QLabel("Replay dir"));
        replay_dir_row->addWidget(replay_dir_input_, 1);
        replay_dir_row->addWidget(choose_replay_button);
        replay_layout->addLayout(replay_dir_row);
        left_layout->addWidget(replay_group);

        auto* right = new QWidget;
        auto* right_layout = new QVBoxLayout(right);
        auto* details_group = new QGroupBox("Review Details");
        auto* details_layout = new QVBoxLayout(details_group);
        review_details_ = new QPlainTextEdit;
        review_details_->setReadOnly(true);
        details_layout->addWidget(review_details_);
        right_layout->addWidget(details_group);

        splitter->addWidget(left);
        splitter->addWidget(right);
        splitter->setStretchFactor(0, 2);
        splitter->setStretchFactor(1, 3);
        layout->addWidget(splitter);

        connect(refresh_queue_button, &QPushButton::clicked, this, [this]() { refresh_review_items(); });
        connect(choose_queue_button, &QPushButton::clicked, this, [this]() {
            const QString dir = QFileDialog::getExistingDirectory(this, "Choose review queue directory", review_queue_dir_input_->text());
            if (!dir.isEmpty()) {
                review_queue_dir_input_->setText(dir);
                refresh_review_items();
            }
        });
        connect(choose_replay_button, &QPushButton::clicked, this, [this]() {
            const QString dir = QFileDialog::getExistingDirectory(this, "Choose replay directory", replay_dir_input_->text());
            if (!dir.isEmpty()) {
                replay_dir_input_->setText(dir);
            }
        });
        connect(review_items_, &QListWidget::currentRowChanged, this, [this](int row) { show_review_item(row); });
        connect(approve_button, &QPushButton::clicked, this, [this]() { apply_review_decision("approved"); });
        connect(reject_button, &QPushButton::clicked, this, [this]() { apply_review_decision("rejected"); });
        connect(replay_button, &QPushButton::clicked, this, [this]() { replay_selected_item(); });
        connect(open_review_file_button, &QPushButton::clicked, this, [this]() { open_review_file(); });

        return tab;
    }

    QWidget* build_files_tab() {
        auto* tab = new QWidget;
        auto* layout = new QVBoxLayout(tab);
        auto* splitter = new QSplitter;

        auto* left = new QWidget;
        auto* left_layout = new QVBoxLayout(left);

        auto* rules_group = new QGroupBox("Rules File");
        auto* rules_layout = new QVBoxLayout(rules_group);
        auto* rules_row = new QHBoxLayout;
        rules_file_input_ = new QLineEdit("examples/rules/raw-live.json");
        auto* choose_rules_button = new QPushButton("Choose File");
        auto* load_rules_button = new QPushButton("Load Rules");
        rules_row->addWidget(new QLabel("Path"));
        rules_row->addWidget(rules_file_input_, 1);
        rules_row->addWidget(choose_rules_button);
        rules_row->addWidget(load_rules_button);
        rules_layout->addLayout(rules_row);
        left_layout->addWidget(rules_group);

        auto* jsonl_group = new QGroupBox("Audit / Action Streams");
        auto* jsonl_layout = new QVBoxLayout(jsonl_group);

        auto* audit_row = new QHBoxLayout;
        audit_file_input_ = new QLineEdit("ghostline_audit.jsonl");
        auto* choose_audit_button = new QPushButton("Choose Audit");
        auto* load_audit_button = new QPushButton("Load Audit");
        audit_row->addWidget(new QLabel("Audit"));
        audit_row->addWidget(audit_file_input_, 1);
        audit_row->addWidget(choose_audit_button);
        audit_row->addWidget(load_audit_button);

        auto* action_row = new QHBoxLayout;
        actions_file_input_ = new QLineEdit("ghostline_actions.jsonl");
        auto* choose_actions_button = new QPushButton("Choose Actions");
        auto* load_actions_button = new QPushButton("Load Actions");
        action_row->addWidget(new QLabel("Actions"));
        action_row->addWidget(actions_file_input_, 1);
        action_row->addWidget(choose_actions_button);
        action_row->addWidget(load_actions_button);

        file_entries_ = new QListWidget;

        jsonl_layout->addLayout(audit_row);
        jsonl_layout->addLayout(action_row);
        jsonl_layout->addWidget(file_entries_, 1);
        left_layout->addWidget(jsonl_group, 1);

        auto* right = new QWidget;
        auto* right_layout = new QVBoxLayout(right);
        auto* details_group = new QGroupBox("File Details");
        auto* details_layout = new QVBoxLayout(details_group);
        file_details_ = new QPlainTextEdit;
        file_details_->setReadOnly(true);
        details_layout->addWidget(file_details_);
        right_layout->addWidget(details_group);

        splitter->addWidget(left);
        splitter->addWidget(right);
        splitter->setStretchFactor(0, 2);
        splitter->setStretchFactor(1, 3);
        layout->addWidget(splitter);

        connect(choose_rules_button, &QPushButton::clicked, this, [this]() { choose_rules_file(); });
        connect(load_rules_button, &QPushButton::clicked, this, [this]() { load_rules_file(); });
        connect(choose_audit_button, &QPushButton::clicked, this, [this]() { choose_audit_file(); });
        connect(load_audit_button, &QPushButton::clicked, this, [this]() { load_jsonl_file(audit_file_input_, "audit"); });
        connect(choose_actions_button, &QPushButton::clicked, this, [this]() { choose_actions_file(); });
        connect(load_actions_button, &QPushButton::clicked, this, [this]() { load_jsonl_file(actions_file_input_, "actions"); });
        connect(file_entries_, &QListWidget::currentRowChanged, this, [this](int row) { show_file_entry(row); });

        return tab;
    }

    PidSearchQuery current_query() const {
        PidSearchQuery query;
        query.process_contains = to_std_string(process_input_->text().trimmed());
        query.state = to_std_string(state_input_->text().trimmed());
        query.listen_only = listen_only_input_->isChecked();
        query.established_only = established_only_input_->isChecked();

        bool ok = false;
        const qlonglong pid = pid_input_->text().trimmed().toLongLong(&ok);
        if (ok) {
            query.pid = pid;
        }

        const int port = port_input_->text().trimmed().toInt(&ok);
        if (ok) {
            query.port = port;
        }
        return query;
    }

    void run_search() {
        try {
            current_results_ = query_tcp_processes(current_query());
            search_results_->clear();
            for (const auto& entry : current_results_) {
                search_results_->addItem(to_qstring(process_summary(entry)));
            }
            if (!current_results_.empty()) {
                search_results_->setCurrentRow(0);
            } else {
                target_details_->setPlainText("No TCP PID matches found.");
            }
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Ghostline Search", to_qstring(error.what()));
        }
    }

    void save_profile_from_search() {
        try {
            const QString dir = profiles_dir_input_->text().trimmed();
            const QString file = profile_file_input_->text().trimmed();
            if (dir.isEmpty() || file.isEmpty()) {
                QMessageBox::warning(this, "Save Profile", "Choose a profile directory and filename first.");
                return;
            }

            TargetProfile profile;
            profile.label = to_std_string(profile_label_input_->text().trimmed());
            if (profile.label.empty()) {
                profile.label = "target-profile";
            }
            profile.query = current_query();
            profile.matches = current_results_;

            const std::filesystem::path path = std::filesystem::path(to_std_string(dir)) / to_std_string(file);
            save_target_profile(path.string(), profile);
            refresh_profiles();
            QMessageBox::information(this, "Save Profile", "Saved target profile to:\n" + to_qstring(path.string()));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Save Profile", to_qstring(error.what()));
        }
    }

    void refresh_profiles() {
        try {
            current_profile_paths_ = list_target_profiles(to_std_string(profiles_dir_input_->text().trimmed()));
            profiles_list_->clear();
            for (const auto& path : current_profile_paths_) {
                profiles_list_->addItem(to_qstring(std::filesystem::path(path).filename().string()));
            }
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Profiles", to_qstring(error.what()));
        }
    }

    void show_search_result(int row) {
        if (row < 0 || static_cast<std::size_t>(row) >= current_results_.size()) {
            return;
        }
        target_details_->setPlainText(to_qstring(process_detail(current_results_[static_cast<std::size_t>(row)])));
    }

    void show_profile_result(int row) {
        if (row < 0 || static_cast<std::size_t>(row) >= current_profile_paths_.size()) {
            return;
        }
        try {
            const TargetProfile profile = load_target_profile(current_profile_paths_[static_cast<std::size_t>(row)]);
            target_details_->setPlainText(to_qstring(target_profile_to_json(profile)));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Profile", to_qstring(error.what()));
        }
    }

    void load_selected_profile_into_search() {
        const int row = profiles_list_->currentRow();
        if (row < 0 || static_cast<std::size_t>(row) >= current_profile_paths_.size()) {
            QMessageBox::warning(this, "Load Profile", "Select a saved profile first.");
            return;
        }
        try {
            const TargetProfile profile = load_target_profile(current_profile_paths_[static_cast<std::size_t>(row)]);
            process_input_->setText(to_qstring(profile.query.process_contains));
            pid_input_->setText(profile.query.pid >= 0 ? QString::number(profile.query.pid) : QString());
            port_input_->setText(profile.query.port >= 0 ? QString::number(profile.query.port) : QString());
            state_input_->setText(to_qstring(profile.query.state));
            listen_only_input_->setChecked(profile.query.listen_only);
            established_only_input_->setChecked(profile.query.established_only);
            profile_label_input_->setText(to_qstring(profile.label));
            run_search();
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Load Profile", to_qstring(error.what()));
        }
    }

    void show_selected_profile_json() {
        const int row = profiles_list_->currentRow();
        if (row < 0 || static_cast<std::size_t>(row) >= current_profile_paths_.size()) {
            QMessageBox::warning(this, "Show Profile", "Select a saved profile first.");
            return;
        }
        show_profile_result(row);
    }

    void open_profile_file() {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          "Open target profile",
                                                          profiles_dir_input_->text(),
                                                          "JSON Files (*.json);;All Files (*)");
        if (path.isEmpty()) {
            return;
        }
        try {
            const TargetProfile profile = load_target_profile(to_std_string(path));
            process_input_->setText(to_qstring(profile.query.process_contains));
            pid_input_->setText(profile.query.pid >= 0 ? QString::number(profile.query.pid) : QString());
            port_input_->setText(profile.query.port >= 0 ? QString::number(profile.query.port) : QString());
            state_input_->setText(to_qstring(profile.query.state));
            listen_only_input_->setChecked(profile.query.listen_only);
            established_only_input_->setChecked(profile.query.established_only);
            profile_label_input_->setText(to_qstring(profile.label));
            profile_file_input_->setText(QFileInfo(path).fileName());
            target_details_->setPlainText(to_qstring(target_profile_to_json(profile)));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Open Profile File", to_qstring(error.what()));
        }
    }

    void refresh_review_items() {
        try {
            current_review_items_ = list_review_items(to_std_string(review_queue_dir_input_->text().trimmed()));
            review_items_->clear();
            for (const auto& item : current_review_items_) {
                review_items_->addItem(to_qstring(review_summary(item)));
            }
            if (!current_review_items_.empty()) {
                review_items_->setCurrentRow(0);
            } else {
                review_details_->setPlainText("No review items found.");
            }
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Review Queue", to_qstring(error.what()));
        }
    }

    void show_review_item(int row) {
        if (row < 0 || static_cast<std::size_t>(row) >= current_review_items_.size()) {
            return;
        }
        review_details_->setPlainText(to_qstring(review_detail(current_review_items_[static_cast<std::size_t>(row)])));
    }

    void open_review_file() {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          "Open review item",
                                                          review_queue_dir_input_->text(),
                                                          "JSON Files (*.json);;All Files (*)");
        if (path.isEmpty()) {
            return;
        }
        try {
            const ActionItem item = load_review_item(to_std_string(path));
            review_details_->setPlainText(to_qstring(review_detail(item)));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Open Review File", to_qstring(error.what()));
        }
    }

    void apply_review_decision(const std::string& status) {
        const int row = review_items_->currentRow();
        if (row < 0 || static_cast<std::size_t>(row) >= current_review_items_.size()) {
            QMessageBox::warning(this, "Review Queue", "Select a review item first.");
            return;
        }
        try {
            update_review_item(to_std_string(review_queue_dir_input_->text().trimmed()),
                               current_review_items_[static_cast<std::size_t>(row)].action_id,
                               status,
                               to_std_string(review_note_input_->text()));
            refresh_review_items();
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Review Queue", to_qstring(error.what()));
        }
    }

    void replay_selected_item() {
        const int row = review_items_->currentRow();
        if (row < 0 || static_cast<std::size_t>(row) >= current_review_items_.size()) {
            QMessageBox::warning(this, "Replay", "Select a review item first.");
            return;
        }
        try {
            const std::string replay_path = replay_review_item(to_std_string(review_queue_dir_input_->text().trimmed()),
                                                               current_review_items_[static_cast<std::size_t>(row)].action_id,
                                                               to_std_string(replay_dir_input_->text().trimmed()),
                                                               to_std_string(review_note_input_->text()));
            refresh_review_items();
            QMessageBox::information(this, "Replay Created", "Replay artifact written to:\n" + to_qstring(replay_path));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Replay", to_qstring(error.what()));
        }
    }

    void choose_rules_file() {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          "Choose rules file",
                                                          rules_file_input_->text(),
                                                          "Rules Files (*.json *.jinja *.j2 *.tfvars *.hcl);;All Files (*)");
        if (!path.isEmpty()) {
            rules_file_input_->setText(path);
        }
    }

    void choose_audit_file() {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          "Choose audit JSONL",
                                                          audit_file_input_->text(),
                                                          "JSONL Files (*.jsonl *.log);;All Files (*)");
        if (!path.isEmpty()) {
            audit_file_input_->setText(path);
        }
    }

    void choose_actions_file() {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          "Choose actions JSONL",
                                                          actions_file_input_->text(),
                                                          "JSONL Files (*.jsonl *.log);;All Files (*)");
        if (!path.isEmpty()) {
            actions_file_input_->setText(path);
        }
    }

    void load_rules_file() {
        const std::string path = to_std_string(rules_file_input_->text().trimmed());
        if (path.empty()) {
            QMessageBox::warning(this, "Load Rules", "Choose a rules file first.");
            return;
        }
        try {
            file_entries_->clear();
            current_file_lines_.clear();
            current_file_type_ = "rules";
            file_details_->setPlainText(to_qstring(read_file_text(path)));
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Load Rules", to_qstring(error.what()));
        }
    }

    void load_jsonl_file(QLineEdit* input, const std::string& type) {
        const std::string path = to_std_string(input->text().trimmed());
        if (path.empty()) {
            QMessageBox::warning(this, "Load File", "Choose a file first.");
            return;
        }
        try {
            current_file_lines_ = read_non_empty_lines(path);
            current_file_type_ = type;
            file_entries_->clear();
            for (const auto& line : current_file_lines_) {
                file_entries_->addItem(to_qstring(summarize_jsonl_line(line)));
            }
            if (!current_file_lines_.empty()) {
                file_entries_->setCurrentRow(0);
            } else {
                file_details_->setPlainText("No entries found.");
            }
        } catch (const std::exception& error) {
            QMessageBox::critical(this, "Load File", to_qstring(error.what()));
        }
    }

    void show_file_entry(int row) {
        if (row < 0 || static_cast<std::size_t>(row) >= current_file_lines_.size()) {
            return;
        }
        file_details_->setPlainText(to_qstring(current_file_lines_[static_cast<std::size_t>(row)]));
    }

    QLineEdit* process_input_ = nullptr;
    QLineEdit* pid_input_ = nullptr;
    QLineEdit* port_input_ = nullptr;
    QLineEdit* state_input_ = nullptr;
    QCheckBox* listen_only_input_ = nullptr;
    QCheckBox* established_only_input_ = nullptr;
    QListWidget* search_results_ = nullptr;
    QPlainTextEdit* target_details_ = nullptr;
    QLineEdit* profiles_dir_input_ = nullptr;
    QLineEdit* profile_label_input_ = nullptr;
    QLineEdit* profile_file_input_ = nullptr;
    QListWidget* profiles_list_ = nullptr;

    QLineEdit* review_queue_dir_input_ = nullptr;
    QLineEdit* replay_dir_input_ = nullptr;
    QListWidget* review_items_ = nullptr;
    QLineEdit* review_note_input_ = nullptr;
    QPlainTextEdit* review_details_ = nullptr;
    QLineEdit* rules_file_input_ = nullptr;
    QLineEdit* audit_file_input_ = nullptr;
    QLineEdit* actions_file_input_ = nullptr;
    QListWidget* file_entries_ = nullptr;
    QPlainTextEdit* file_details_ = nullptr;

    std::vector<ProcessSocketEntry> current_results_;
    std::vector<std::string> current_profile_paths_;
    std::vector<ActionItem> current_review_items_;
    std::vector<std::string> current_file_lines_;
    std::string current_file_type_;
};

} // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    GhostlineOperatorWindow window;
    window.show();
    return app.exec();
}
