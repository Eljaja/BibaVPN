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
        title = "Приложение"

        setContentView(
            TextView(this).apply {
                text = "Загрузка приложений…"
                setPadding(32, 32, 32, 32)
            }
        )

        Thread {
            val rows = loadLauncherApps()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                setContentView(buildList(rows))
            }
        }.start()
    }

    private fun loadLauncherApps(): List<AppRow> {
        val pm = packageManager
        val launchIntent =
            Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
        @Suppress("DEPRECATION")
        return pm.queryIntentActivities(launchIntent, 0)
            .asSequence()
            .filter { it.activityInfo.packageName != packageName }
            .distinctBy { it.activityInfo.packageName }
            .map { ri ->
                AppRow(
                    label = ri.loadLabel(pm).toString(),
                    packageName = ri.activityInfo.packageName
                )
            }
            .sortedBy { it.label.lowercase() }
            .toList()
    }

    private fun buildList(rows: List<AppRow>): RecyclerView {
        return RecyclerView(this).apply {
            layoutManager = LinearLayoutManager(this@PickInstalledPackageActivity)
            adapter =
                object : RecyclerView.Adapter<VH>() {
                    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
                        val row =
                            LayoutInflater.from(parent.context)
                                .inflate(android.R.layout.simple_list_item_2, parent, false)
                        return VH(row)
                    }

                    override fun getItemCount(): Int = rows.size

                    override fun onBindViewHolder(holder: VH, position: Int) {
                        val row = rows[position]
                        holder.text1.text = row.label
                        holder.text2.text = row.packageName
                        holder.itemView.setOnClickListener {
                            setResult(
                                RESULT_OK,
                                Intent().putExtra(EXTRA_PACKAGE_NAME, row.packageName)
                            )
                            finish()
                        }
                    }
                }
        }
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

    private data class AppRow(val label: String, val packageName: String)

    private class VH(view: View) : RecyclerView.ViewHolder(view) {
        val text1: TextView = view.findViewById(android.R.id.text1)
        val text2: TextView = view.findViewById(android.R.id.text2)
    }
}
