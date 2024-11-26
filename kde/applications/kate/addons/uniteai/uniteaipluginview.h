/*
    SPDX-FileCopyrightText:

    SPDX-License-Identifier: MIT
*/

#pragma once

#include <QObject>
#include <memory>

class UniteAIPlugin;

namespace KTextEditor
{
class MainWindow;
}

enum class State { None, Started, Running, Shutdown };

class UniteAIPluginView
{
public:
    // only needs a factory; no other public interface
    static QObject *new_(UniteAIPlugin *plugin, KTextEditor::MainWindow *mainWin);


};

namespace utils
{
// template helper
// function bind helpers
template<typename R, typename T, typename Tp, typename... Args>
inline std::function<R(Args...)> mem_fun(R (T::*pm)(Args...), Tp object)
{
    return [object, pm](Args... args) {
        return (object->*pm)(std::forward<Args>(args)...);
    };
}

template<typename R, typename T, typename Tp, typename... Args>
inline std::function<R(Args...)> mem_fun(R (T::*pm)(Args...) const, Tp object)
{
    return [object, pm](Args... args) {
        return (object->*pm)(std::forward<Args>(args)...);
    };
}

// prevent argument deduction
template<typename T>
struct identity {
    typedef T type;
};

} // namespace utils
