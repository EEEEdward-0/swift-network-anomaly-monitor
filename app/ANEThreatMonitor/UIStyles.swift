import SwiftUI

// 主操作按钮：用于新增、开始、确认等高优先级动作。
struct PrimaryAnimatedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
    }
}

// 次级操作按钮：用于刷新、导出、辅助操作等中性动作。
struct SecondaryAnimatedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
    }
}

// 危险操作按钮：用于删除、清空等不可逆动作。
struct DangerAnimatedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
    }
}

// 紧凑危险按钮：用于历史记录等行级删除动作。
struct CompactDangerAnimatedButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
    }
}

// 统一卡片式 GroupBox 样式。
struct CleanGroupBoxStyle: GroupBoxStyle {
    var fill: Color
    var stroke: Color

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            configuration.label
            configuration.content
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(fill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(stroke, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.14), radius: 16, x: 0, y: 8)
    }
}
