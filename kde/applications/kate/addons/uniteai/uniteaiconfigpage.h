/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#pragma once

#include <KTextEditor/ConfigPage>

class UniteAIPlugin;

namespace Ui
{
class AIConfigWidget;
}

class AIConfigPage : public KTextEditor::ConfigPage
{
    Q_OBJECT

public:
    explicit AIConfigPage(QWidget *parent = nullptr, UniteAIPlugin *plugin = nullptr);
    ~AIConfigPage() override;

    QString name() const override;
    QString fullName() const override;
    QIcon icon() const override;

public Q_SLOTS:
    void apply() override;
    void defaults() override;
    void reset() override;
    void configTextChanged();
    void configUrlChanged();
    void updateHighlighters();
    void showContextMenuAllowedBlocked(const QPoint &pos);

private:
    void readUserConfig(const QString &fileName);
    void updateConfigTextErrorState();

    Ui::AIConfigWidget *ui;
    UniteAIPlugin *m_plugin;
};
