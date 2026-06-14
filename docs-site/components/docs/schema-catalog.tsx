"use client";

import Link from "next/link";
import catalog from "@/data/database-schema.json";
import { DatabaseTable } from "@/components/docs/mdx-components";

type SchemaField = {
	logical: string;
	name: string;
	type: string;
	description: string;
	isPrimaryKey?: boolean;
	isOptional?: boolean;
	isUnique?: boolean;
	isForeignKey?: boolean;
	references?: {
		model: string;
		field: string;
		onDelete?: string;
	};
};

type SchemaTable = {
	logical: string;
	name: string;
	order?: number;
	plugin: string | null;
	note?: string;
	fields: SchemaField[];
};

function toDatabaseTableFields(fields: SchemaField[]) {
	return fields.map((field) => ({
		name: field.name,
		type: field.type,
		description: field.description,
		isPrimaryKey: field.isPrimaryKey,
		isOptional: field.isOptional,
		isUnique: field.isUnique,
		isForeignKey: field.isForeignKey,
		references: field.references
			? {
					model: field.references.model,
					field: field.references.field,
					onDelete: field.references.onDelete as
						| "no action"
						| "restrict"
						| "cascade"
						| "set null"
						| "set default"
						| undefined,
				}
			: undefined,
	}));
}

function TableSection({ table }: { table: SchemaTable }) {
	return (
		<div className="not-prose scroll-mt-24" id={`table-${table.name}`}>
			<div className="mb-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
				<h3 className="m-0 font-mono text-sm font-medium text-foreground/90">
					{table.name}
				</h3>
				<span className="text-xs text-muted-foreground">
					logical: <code>{table.logical}</code>
				</span>
				{table.note ? (
					<span className="text-xs text-muted-foreground">{table.note}</span>
				) : null}
			</div>
			<DatabaseTable
				name={table.name}
				fields={toDatabaseTableFields(table.fields)}
			/>
		</div>
	);
}

export function SchemaCatalog() {
	const data = catalog;

	return (
		<div className="not-prose space-y-10">
			<div className="rounded-lg border bg-muted/20 px-4 py-3 text-sm text-muted-foreground">
				<p className="m-0">
					Generated from{" "}
					<code className="text-foreground/80">{data.source.command}</code>.
					Last updated{" "}
					<time dateTime={data.generatedAt}>
						{new Date(data.generatedAt).toLocaleDateString("en-US", {
							year: "numeric",
							month: "short",
							day: "numeric",
						})}
					</time>
					. Regenerate with{" "}
					<code className="text-foreground/80">
						pnpm generate:database-schema
					</code>
					.
				</p>
				<p className="mb-0 mt-2">
					{data.summary.tableCount} tables total ({data.summary.coreTableCount}{" "}
					core, {data.summary.pluginTableCount} from plugins). Your effective
					schema depends on which plugins you enable in{" "}
					<code className="text-foreground/80">rustauth.toml</code> and
					application code.
				</p>
			</div>

			<section className="space-y-6">
				<h2 className="m-0 text-lg font-semibold" id="core-tables">
					Core tables
				</h2>
				<p className="m-0 text-sm text-muted-foreground">
					Always present with a SQL adapter. See also{" "}
					<Link href="/docs/concepts/database" className="underline">
						Database
					</Link>
					.
				</p>
				<div className="space-y-8">
					{data.coreTables.map((table) => (
						<TableSection key={table.logical} table={table} />
					))}
				</div>
			</section>

			<section className="space-y-8">
				<h2 className="m-0 text-lg font-semibold" id="plugin-tables">
					Plugin tables
				</h2>
				<p className="m-0 text-sm text-muted-foreground">
					Added when the matching plugin is enabled and you run{" "}
					<code className="text-foreground/80">rustauth db migrate</code>.
				</p>
				{data.pluginSections.map((section) => (
					<div key={section.plugin} className="space-y-6 scroll-mt-24">
						<div
							className="flex flex-wrap items-center gap-2"
							id={`plugin-${section.plugin}`}
						>
							<h3 className="m-0 text-base font-semibold">{section.plugin}</h3>
							{section.docHref ? (
								<Link
									href={section.docHref}
									className="text-sm text-muted-foreground underline"
								>
									plugin docs
								</Link>
							) : null}
						</div>
						<div className="space-y-8">
							{section.tables.map((table) => (
								<TableSection key={table.logical} table={table} />
							))}
						</div>
					</div>
				))}
			</section>

			<section className="space-y-4">
				<h2 className="m-0 text-lg font-semibold" id="plugins-without-tables">
					Plugins without dedicated tables
				</h2>
				<p className="m-0 text-sm text-muted-foreground">
					These plugins reuse core tables or do not persist state in the
					database.
				</p>
				<ul className="m-0 list-disc space-y-2 pl-5 text-sm text-muted-foreground">
					{data.pluginsWithoutTables.map((plugin) => (
						<li key={plugin.id}>
							<code className="text-foreground/80">{plugin.id}</code> —{" "}
							{plugin.note}
						</li>
					))}
				</ul>
			</section>
		</div>
	);
}
