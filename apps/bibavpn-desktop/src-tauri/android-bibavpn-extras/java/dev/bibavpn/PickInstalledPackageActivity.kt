package dev.bibavpn

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/**
 * Список приложений с лаунчером — для добавления в split-tunnel (обход VPN).
 */
class PickInstalledPackageActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pm = packageManager
        val launchIntent =
            Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
        @Suppress("DEPRECATION")
        val resolves =
            pm.queryIntentActivities(launchIntent, 0)
                .filter { it.activityInfo.packageName != packageName }
                .distinctBy { it.activityInfo.packageName }
                .sortedBy { ri ->
                    ri.loadLabel(pm).toString().lowercase()
                }

        val rv = RecyclerView(this)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter =
            object : RecyclerView.Adapter<VH>() {
                override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
                    val row =
                        LayoutInflater.from(parent.context)
                            .inflate(android.R.layout.simple_list_item_2, parent, false)
                    return VH(row)
                }

                override fun getItemCount(): Int = resolves.size

                override fun onBindViewHolder(holder: VH, position: Int) {
                    val ri = resolves[position]
                    val pkg = ri.activityInfo.packageName
                    holder.text1.text = ri.loadLabel(pm).toString()
                    holder.text2.text = pkg
                    holder.itemView.setOnClickListener {
                        setResult(RESULT_OK, Intent().putExtra(EXTRA_PACKAGE_NAME, pkg))
                        finish()
                    }
                }
            }
        setContentView(rv)
        title = "Приложение"
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        setResult(RESULT_CANCELED)
        @Suppress("DEPRECATION")
        super.onBackPressed()
    }

    companion object {
        const val EXTRA_PACKAGE_NAME = "dev.bibavpn.EXTRA_SPLIT_TUNNEL_PKG"
    }

    private class VH(view: View) : RecyclerView.ViewHolder(view) {
        val text1: TextView = view.findViewById(android.R.id.text1)
        val text2: TextView = view.findViewById(android.R.id.text2)
    }
}
