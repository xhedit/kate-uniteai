/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#pragma once

#include <QUrl>
#include <QVariant>

#include <KTextEditor/Message>
#include <KTextEditor/Plugin>

#include <map>
#include <set>

class LSPClientServerManager;

class UniteAIPlugin : public KTextEditor::Plugin
{
    Q_OBJECT

public:
    explicit UniteAIPlugin(QObject *parent = nullptr, const QList<QVariant> & = QList<QVariant>());
    ~UniteAIPlugin() override;

    QObject *createView(KTextEditor::MainWindow *mainWindow) override;

    int configPages() const override;
    KTextEditor::ConfigPage *configPage(int number = 0, QWidget *parent = nullptr) override;

    void readConfig();
    void writeConfig() const;

    // path for local setting files, auto-created on load
    const QString m_settingsPath;

    // settings
    QUrl m_configPath;

    // debug mode?
    const bool m_debugMode;

    // get current config path
    QUrl configPath() const
    {
        return m_configPath;
    }


Q_SIGNALS:
    // signal settings update
    void update() const;

    void showMessage(KTextEditor::Message::MessageType level, const QString &msg);

private:
    // server manager to pass along
};
