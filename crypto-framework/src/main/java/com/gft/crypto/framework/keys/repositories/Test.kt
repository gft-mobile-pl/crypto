package com.gft.crypto.framework.keys.repositories

import android.content.SharedPreferences

class Test(private val sp: SharedPreferences) : SharedPreferences by sp {
    override fun edit(): SharedPreferences.Editor = Editor(sp.edit())

    private class Editor(editor: SharedPreferences.Editor) : SharedPreferences.Editor by editor {
        override fun clear(): SharedPreferences.Editor {
            TODO("Not yet implemented")
        }
    }
}